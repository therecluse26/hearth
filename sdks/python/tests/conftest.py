"""Shared pytest fixtures for the Hearth Python SDK test suite."""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def rsa_private_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_private_key_2():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def ec_private_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def rsa_jwk(rsa_private_key):
    from jwt.algorithms import RSAAlgorithm
    pub = rsa_private_key.public_key()
    jwk = json.loads(RSAAlgorithm.to_jwk(pub))
    jwk.update({"kid": "rsa-1", "use": "sig", "alg": "RS256"})
    return jwk


@pytest.fixture(scope="session")
def rsa_jwk_2(rsa_private_key_2):
    from jwt.algorithms import RSAAlgorithm
    pub = rsa_private_key_2.public_key()
    jwk = json.loads(RSAAlgorithm.to_jwk(pub))
    jwk.update({"kid": "rsa-2", "use": "sig", "alg": "RS256"})
    return jwk


@pytest.fixture(scope="session")
def ec_jwk(ec_private_key):
    from jwt.algorithms import ECAlgorithm
    pub = ec_private_key.public_key()
    jwk = json.loads(ECAlgorithm.to_jwk(pub))
    jwk.update({"kid": "ec-1", "use": "sig", "alg": "ES256"})
    return jwk


# ---------------------------------------------------------------------------
# JWT factories
# ---------------------------------------------------------------------------

def make_rsa_jwt(
    private_key,
    kid: str,
    payload: Dict[str, Any],
) -> str:
    import jwt
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def make_ec_jwt(
    private_key,
    kid: str,
    payload: Dict[str, Any],
) -> str:
    import jwt
    return jwt.encode(payload, private_key, algorithm="ES256", headers={"kid": kid})


def valid_payload(
    issuer: str = "https://auth.example.com",
    audience: str = "my-client",
    skew: int = 0,
) -> Dict[str, Any]:
    now = int(time.time())
    return {
        "sub": "user-123",
        "iss": issuer,
        "aud": audience,
        "iat": now - skew,
        "exp": now + 3600,
    }


# ---------------------------------------------------------------------------
# Mock HTTP client factory
# ---------------------------------------------------------------------------

def mock_http(
    discovery_doc: Optional[Dict[str, Any]] = None,
    jwks_doc: Optional[Dict[str, Any]] = None,
    jwks_headers: Optional[Dict[str, str]] = None,
) -> MagicMock:
    """Build a mock httpx.Client for unit tests."""
    ISSUER = "https://auth.example.com"
    disc = discovery_doc or {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "introspection_endpoint": f"{ISSUER}/introspect",
    }

    def _make_response(json_body, status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.json.return_value = json_body
        r.headers = headers or {}
        r.raise_for_status = MagicMock()
        if status >= 400:
            from httpx import HTTPStatusError
            r.raise_for_status.side_effect = HTTPStatusError(
                str(status), request=MagicMock(), response=r
            )
        return r

    def _get(url, **kwargs):
        if "openid-configuration" in url:
            return _make_response(disc)
        if "jwks.json" in url or "jwks_uri" in url or url == disc.get("jwks_uri", ""):
            return _make_response(
                jwks_doc or {"keys": []},
                headers=jwks_headers or {},
            )
        return _make_response({}, 404)

    http = MagicMock()
    http.get.side_effect = _get
    http.post.return_value = _make_response({})
    return http
