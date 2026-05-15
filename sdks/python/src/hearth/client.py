"""HearthClient — spec §1–§3.

Single entry point for OIDC discovery, JWKS token verification,
RFC 7662 introspection, and OAuth 2.0 flows.

All OIDC endpoint URLs are auto-discovered from
``{issuer_url}/.well-known/openid-configuration`` on first use (spec §1).
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

import httpx
import jwt

from ._jwks import JwksCache
from .errors import (
    ConfigurationError,
    DiscoveryError,
    HearthError,
    IntrospectionError,
    JwksFetchError,
    TokenAudienceError,
    TokenClaimsError,
    TokenExpiredError,
    TokenIssuerError,
    TokenNotYetValidError,
    TokenVerificationError,
)
from .types import (
    AuthorizeResponse,
    BootstrapResponse,
    IntrospectionResult,
    JwksDocument,
    MePermissionsResponse,
    OAuthClient,
    RegisterClientRequest,
    TokenResponse,
    UserInfoResponse,
)
from .verified_token import VerifiedToken

_DEFAULT_TIMEOUT: float = 10.0
_DEFAULT_CLOCK_SKEW: int = 60   # seconds


class HearthClient:
    """Single entry point for Hearth auth flows and token operations.

    Parameters
    ----------
    issuer_url:
        Root URL of the Hearth instance.  All endpoint URLs are
        auto-discovered from ``{issuer_url}/.well-known/openid-configuration``.
    client_id:
        OAuth 2.0 client identifier.  Required for flows that need a
        client identity and for audience validation in ``verify_token``.
    client_secret:
        OAuth 2.0 client secret.  Required for confidential-client flows
        and for introspection.
    jwks_ttl:
        Override JWKS cache TTL in seconds.  Defaults to respecting the
        ``Cache-Control: max-age`` header, falling back to 5 minutes.
    introspection_endpoint:
        Override the introspection URL discovered from ``openid-configuration``.
    http_timeout:
        Timeout in seconds for all outbound HTTP calls.  Defaults to 10s.
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        jwks_ttl: Optional[int] = None,
        introspection_endpoint: Optional[str] = None,
        http_timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        if not issuer_url:
            raise ConfigurationError("issuer_url is required", field="issuer_url")
        self._issuer = issuer_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._jwks_ttl = jwks_ttl
        self._introspection_override = introspection_endpoint
        self._http = httpx.Client(timeout=http_timeout)
        self._discovery_lock = threading.Lock()
        self._discovery_doc: Optional[Dict[str, Any]] = None
        self._jwks_cache: Optional[JwksCache] = None

    # ------------------------------------------------------------------
    # §1 — OIDC discovery (lazy, thread-safe double-checked locking)
    # ------------------------------------------------------------------

    def _get_discovery(self) -> Dict[str, Any]:
        if self._discovery_doc is not None:
            return self._discovery_doc
        with self._discovery_lock:
            if self._discovery_doc is not None:
                return self._discovery_doc
            url = f"{self._issuer}/.well-known/openid-configuration"
            try:
                resp = self._http.get(url)
                resp.raise_for_status()
                doc: Dict[str, Any] = resp.json()
            except Exception as exc:
                raise DiscoveryError(
                    f"failed to fetch discovery document: {type(exc).__name__}", url=url
                ) from exc

            jwks_uri = doc.get("jwks_uri")
            if not jwks_uri:
                raise DiscoveryError("discovery document is missing 'jwks_uri'", url=url)

            self._jwks_cache = JwksCache(
                jwks_uri=jwks_uri,
                http=self._http,
                override_ttl=self._jwks_ttl,
            )
            self._discovery_doc = doc
            return doc

    @property
    def _jwks(self) -> JwksCache:
        if self._jwks_cache is None:
            self._get_discovery()
        assert self._jwks_cache is not None
        return self._jwks_cache

    # ------------------------------------------------------------------
    # §2 — Token verification
    # ------------------------------------------------------------------

    def verify_token(
        self,
        token: str,
        audience: Optional[str] = None,
        clock_skew: int = _DEFAULT_CLOCK_SKEW,
    ) -> VerifiedToken:
        """Verify *token* and return a :class:`VerifiedToken`.

        Validates signature, ``exp``, ``iss``, ``aud``, and ``iat`` in
        the order required by spec §2.  Re-fetches JWKS on ``kid`` cache
        miss (rule 3).

        :raises TokenVerificationError: malformed JWT, bad signature, or
            unsupported algorithm.
        :raises TokenExpiredError: ``exp`` is in the past.
        :raises TokenClaimsError: ``iss``, ``aud``, or ``iat`` mismatch.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            raise TokenVerificationError("malformed JWT header") from exc

        alg = header.get("alg", "")
        if alg not in ("RS256", "ES256"):
            raise TokenVerificationError(f"unsupported algorithm: {alg!r}")

        kid = header.get("kid", "")
        key = self._jwks.get_key(kid)
        payload = self._decode_and_verify_signature(token, key, alg)
        self._validate_claims(payload, audience=audience, clock_skew=clock_skew)
        return VerifiedToken(payload)

    def _decode_and_verify_signature(
        self, token: str, key: Any, alg: str
    ) -> Dict[str, Any]:
        try:
            return jwt.decode(
                token,
                key,
                algorithms=[alg],
                options={
                    "verify_exp": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_iat": False,  # we validate iat manually
                    "verify_nbf": False,  # we validate nbf manually
                },
            )
        except jwt.InvalidSignatureError as exc:
            raise TokenVerificationError("invalid token signature") from exc
        except jwt.DecodeError as exc:
            raise TokenVerificationError("JWT decode failed") from exc
        except Exception as exc:
            raise TokenVerificationError("token verification failed") from exc

    def _validate_claims(
        self,
        payload: Dict[str, Any],
        audience: Optional[str],
        clock_skew: int,
    ) -> None:
        now = int(time.time())

        # 1. exp
        exp = payload.get("exp")
        if exp is not None and now > int(exp) + clock_skew:
            raise TokenExpiredError(expired_at=int(exp))

        # 2. iss
        iss = payload.get("iss")
        if iss is not None and str(iss) != self._issuer:
            raise TokenIssuerError(expected=self._issuer, actual=str(iss))

        # 3. aud
        expected_aud = audience or self._client_id
        if expected_aud is not None:
            aud_val = payload.get("aud")
            if aud_val is not None:
                aud_list = (
                    [str(a) for a in aud_val]
                    if isinstance(aud_val, list)
                    else [str(aud_val)]
                )
                if expected_aud not in aud_list:
                    raise TokenAudienceError(expected=expected_aud, actual=aud_list)

        # 4. iat — must not be unreasonably in the future
        iat = payload.get("iat")
        if iat is not None and int(iat) > now + clock_skew:
            raise TokenClaimsError("iat claim is in the future")

        # 5. nbf (optional guard)
        nbf = payload.get("nbf")
        if nbf is not None and now < int(nbf) - clock_skew:
            raise TokenNotYetValidError(not_before=int(nbf))

    # ------------------------------------------------------------------
    # §3 — Token introspection (RFC 7662)
    # ------------------------------------------------------------------

    def introspect(self, token: str) -> IntrospectionResult:
        """Introspect *token* per RFC 7662.

        Results are **never** cached (RFC 7662 §2.1 — token state can
        change at any time).

        :raises ConfigurationError: ``client_id``/``client_secret`` absent.
        :raises IntrospectionError: network failure or server error.
        """
        if not self._client_id or not self._client_secret:
            raise ConfigurationError(
                "client_id and client_secret are required for introspection",
                field="client_secret",
            )

        endpoint = self._introspection_override
        if not endpoint:
            doc = self._get_discovery()
            endpoint = doc.get("introspection_endpoint")
            if not endpoint:
                raise IntrospectionError(
                    "introspection_endpoint not found in discovery document"
                )

        try:
            resp = self._http.post(
                endpoint,
                data={"token": token},
                auth=(self._client_id, self._client_secret),
            )
            resp.raise_for_status()
            data: Dict[str, Any] = resp.json()
        except Exception as exc:
            raise IntrospectionError(
                f"introspection request failed: {type(exc).__name__}"
            ) from exc

        return IntrospectionResult._from_dict(data)

    # ------------------------------------------------------------------
    # OAuth 2.0 flows
    # ------------------------------------------------------------------

    def authorize(
        self,
        redirect_uri: str,
        scope: str = "openid",
        state: str = "",
        resource: Optional[str] = None,
    ) -> AuthorizeResponse:
        """Build an authorization redirect URL."""
        if not self._client_id:
            raise ConfigurationError("client_id is required for authorize()", field="client_id")
        doc = self._get_discovery()
        endpoint = doc.get("authorization_endpoint", f"{self._issuer}/authorize")
        params: Dict[str, str] = {
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
        }
        if resource:
            params["resource"] = resource
        resp = self._http.get(endpoint, params=params)
        if resp.status_code != 200:
            raise HearthError(f"authorize failed: HTTP {resp.status_code}")
        return AuthorizeResponse(**resp.json())

    def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> TokenResponse:
        """Exchange an authorization code for tokens."""
        if not self._client_id:
            raise ConfigurationError("client_id is required", field="client_id")
        doc = self._get_discovery()
        endpoint = doc.get("token_endpoint", f"{self._issuer}/token")
        body: Dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
        }
        if self._client_secret:
            body["client_secret"] = self._client_secret
        if code_verifier:
            body["code_verifier"] = code_verifier
        resp = self._http.post(endpoint, data=body)
        if resp.status_code != 200:
            raise HearthError(f"token exchange failed: HTTP {resp.status_code}")
        return TokenResponse(**resp.json())

    def refresh_tokens(self, refresh_token: str) -> TokenResponse:
        """Refresh an access token."""
        if not self._client_id:
            raise ConfigurationError("client_id is required", field="client_id")
        doc = self._get_discovery()
        endpoint = doc.get("token_endpoint", f"{self._issuer}/token")
        body: Dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._client_id,
        }
        if self._client_secret:
            body["client_secret"] = self._client_secret
        resp = self._http.post(endpoint, data=body)
        if resp.status_code != 200:
            raise HearthError(f"token refresh failed: HTTP {resp.status_code}")
        return TokenResponse(**resp.json())

    def userinfo(self, access_token: str) -> UserInfoResponse:
        """Retrieve OpenID Connect userinfo."""
        doc = self._get_discovery()
        endpoint = doc.get("userinfo_endpoint", f"{self._issuer}/userinfo")
        resp = self._http.get(
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status_code == 401:
            # Rule 4: re-fetch JWKS on 401 from a protected resource.
            self._jwks.force_refresh()
        if resp.status_code != 200:
            raise HearthError(f"userinfo failed: HTTP {resp.status_code}")
        return UserInfoResponse(**resp.json())

    def jwks(self) -> JwksDocument:
        """Fetch the JSON Web Key Set document directly."""
        doc = self._get_discovery()
        jwks_uri = doc.get("jwks_uri", f"{self._issuer}/.well-known/jwks.json")
        resp = self._http.get(jwks_uri)
        if resp.status_code != 200:
            raise JwksFetchError(
                f"JWKS endpoint returned HTTP {resp.status_code}", url=jwks_uri
            )
        return JwksDocument(**resp.json())

    def discovery(self) -> Dict[str, Any]:
        """Return the raw OIDC discovery document."""
        return self._get_discovery()

    def register_client(self, req: RegisterClientRequest) -> OAuthClient:
        """Register a new OAuth client."""
        doc = self._get_discovery()
        endpoint = doc.get("registration_endpoint", f"{self._issuer}/clients")
        resp = self._http.post(endpoint, json=req.model_dump(exclude_none=True))
        if resp.status_code != 200:
            raise HearthError(f"client registration failed: HTTP {resp.status_code}")
        return OAuthClient(**resp.json())

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self) -> "HearthClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def bootstrap(base_url: str) -> BootstrapResponse:
        """Bootstrap a dev server (dev mode only)."""
        resp = httpx.post(f"{base_url.rstrip('/')}/admin/bootstrap")
        if resp.status_code != 200:
            raise HearthError(f"bootstrap failed: HTTP {resp.status_code}")
        return BootstrapResponse(**resp.json())
