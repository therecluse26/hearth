"""Spec §6 — Flask and FastAPI middleware.

Both adapters:
- Extract ``Authorization: Bearer <token>`` from the request.
- Verify the token via JWKS by default; introspection is opt-in.
- Inject :class:`VerifiedToken` into the request context on success.
- Return ``401`` with ``WWW-Authenticate: Bearer realm="hearth"`` on
  missing or invalid tokens.
- Return ``403`` when the token is valid but lacks a required scope/role.
- Never call the downstream handler on auth failure.

Neither adapter has a hard dependency on Flask or FastAPI at import time.
Install the relevant framework to use the corresponding adapter.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from .errors import (
    MiddlewareError,
    TokenClaimsError,
    TokenExpiredError,
    TokenVerificationError,
)
from .verified_token import VerifiedToken

_WWW_AUTH = 'Bearer realm="hearth"'


# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------

def hearth_flask(
    client: "HearthClient",  # noqa: F821
    required_scope: Optional[str] = None,
    required_role: Optional[str] = None,
    use_introspection: bool = False,
) -> Callable:
    """Flask route decorator that enforces Bearer-token authentication.

    Usage::

        from flask import Flask, g
        from hearth import HearthClient
        from hearth.middleware import hearth_flask

        app = Flask(__name__)
        hearth = HearthClient(issuer_url="https://auth.example.com", client_id="my-app")

        @app.route("/protected")
        @hearth_flask(hearth)
        def protected():
            token = g.hearth_token          # VerifiedToken
            return {"sub": token.subject}

    :param client: Configured :class:`HearthClient` instance.
    :param required_scope: If set, respond ``403`` when the token lacks
        this scope.
    :param required_role: If set, respond ``403`` when the token lacks
        this role.
    :param use_introspection: Use RFC 7662 introspection instead of local
        JWKS verification.
    """
    from functools import wraps

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                from flask import g, request
            except ImportError as exc:
                raise MiddlewareError(
                    "Flask is not installed; install hearth-sdk[flask]"
                ) from exc

            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _flask_401("missing or invalid Authorization header")

            raw_token = auth[len("Bearer "):]
            token = _resolve_token(client, raw_token, use_introspection)
            if token is None:
                return _flask_401("invalid or expired token")

            if required_scope and not token.has_scope(required_scope):
                return _flask_403("insufficient scope")
            if required_role and not token.has_role(required_role):
                return _flask_403("insufficient role")

            g.hearth_token = token
            return f(*args, **kwargs)

        return wrapper

    return decorator


def _flask_401(message: str):
    from flask import jsonify, make_response

    resp = make_response(jsonify({"error": message}), 401)
    resp.headers["WWW-Authenticate"] = _WWW_AUTH
    return resp


def _flask_403(message: str):
    from flask import jsonify

    return jsonify({"error": message}), 403


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

def hearth_fastapi(
    client: "HearthClient",  # noqa: F821
    required_scope: Optional[str] = None,
    required_role: Optional[str] = None,
    use_introspection: bool = False,
) -> Callable:
    """FastAPI dependency factory that enforces Bearer-token authentication.

    Returns an async dependency function suitable for use with
    ``fastapi.Depends``.

    Usage::

        from fastapi import FastAPI, Depends
        from hearth import HearthClient
        from hearth.middleware import hearth_fastapi

        app = FastAPI()
        hearth = HearthClient(issuer_url="https://auth.example.com", client_id="my-app")
        auth = hearth_fastapi(hearth)

        @app.get("/protected")
        async def protected(token: VerifiedToken = Depends(auth)):
            return {"sub": token.subject}

    :param client: Configured :class:`HearthClient` instance.
    :param required_scope: Respond ``403`` when the token lacks this scope.
    :param required_role: Respond ``403`` when the token lacks this role.
    :param use_introspection: Use RFC 7662 introspection instead of local
        JWKS verification.
    """
    try:
        from fastapi import Depends, HTTPException
        from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    except ImportError as exc:
        raise MiddlewareError(
            "FastAPI is not installed; install hearth-sdk[fastapi]"
        ) from exc

    bearer = HTTPBearer(auto_error=False)

    async def _dep(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    ) -> VerifiedToken:
        if credentials is None:
            raise HTTPException(
                status_code=401,
                detail="missing or invalid Authorization header",
                headers={"WWW-Authenticate": _WWW_AUTH},
            )

        raw_token = credentials.credentials
        token = _resolve_token(client, raw_token, use_introspection)
        if token is None:
            raise HTTPException(
                status_code=401,
                detail="invalid or expired token",
                headers={"WWW-Authenticate": _WWW_AUTH},
            )

        if required_scope and not token.has_scope(required_scope):
            raise HTTPException(status_code=403, detail="insufficient scope")
        if required_role and not token.has_role(required_role):
            raise HTTPException(status_code=403, detail="insufficient role")

        return token

    return _dep


# ---------------------------------------------------------------------------
# Shared resolution helper
# ---------------------------------------------------------------------------

def _resolve_token(
    client: "HearthClient",  # noqa: F821
    raw_token: str,
    use_introspection: bool,
) -> Optional[VerifiedToken]:
    """Verify or introspect *raw_token*; return None on any auth failure."""
    try:
        if use_introspection:
            result = client.introspect(raw_token)
            if not result.active:
                return None
            return result.to_verified_token()
        return client.verify_token(raw_token)
    except (TokenExpiredError, TokenVerificationError, TokenClaimsError):
        return None
    except Exception:
        return None
