"""HearthClient: OAuth auth flows, RBAC predicates, and API operations."""

from typing import Optional, Dict, Any, List
from urllib.parse import urlencode
import json

import httpx
import jwt

from .errors import HearthError
from .types import (
    BootstrapResponse,
    AuthorizeResponse,
    TokenResponse,
    UserInfoResponse,
    MePermissionsResponse,
    JwksDocument,
    OAuthClient,
    RegisterClientRequest,
)


class HearthClient:
    """Client for Hearth OAuth flows, userinfo, and RBAC predicates.

    RBAC predicate methods (has_permission, has_role, in_group, in_org)
    decode the JWT locally — no network call needed.

    Attributes:
        base_url: The Hearth server base URL (e.g. ``https://auth.example.com``).
        realm_id: The realm identifier for all scoped requests.
    """

    def __init__(
        self,
        base_url: str,
        realm_id: str,
        access_token: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self._base = base_url.rstrip("/")
        self._realm = realm_id
        self._token = access_token
        self._http = httpx.Client(
            headers={"X-Realm-ID": realm_id},
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Static bootstrap (dev-only)
    # ------------------------------------------------------------------

    @staticmethod
    def bootstrap(base_url: str) -> BootstrapResponse:
        """Bootstrap a dev server, returning admin credentials (dev mode only)."""
        resp = httpx.post(f"{base_url.rstrip('/')}/admin/bootstrap")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return BootstrapResponse(**resp.json())

    # ------------------------------------------------------------------
    # OAuth flows
    # ------------------------------------------------------------------

    def authorize(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid",
        state: str = "",
        resource: Optional[str] = None,
    ) -> AuthorizeResponse:
        """Initiate an OAuth 2.0 authorization code request."""
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
        }
        if resource:
            params["resource"] = resource

        resp = self._http.get(f"{self._base}/authorize", params=params)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return AuthorizeResponse(**resp.json())

    def exchange_code(
        self,
        code: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> TokenResponse:
        """Exchange an authorization code for tokens."""
        body = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            body["code_verifier"] = code_verifier

        resp = self._http.post(f"{self._base}/token", data=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return TokenResponse(**resp.json())

    def refresh_tokens(
        self,
        refresh_token: str,
        client_id: str,
        client_secret: str,
    ) -> TokenResponse:
        """Refresh an access token."""
        resp = self._http.post(
            f"{self._base}/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return TokenResponse(**resp.json())

    def register_client(self, req: RegisterClientRequest) -> OAuthClient:
        """Register a new OAuth client (requires admin/realm token)."""
        resp = self._http.post(
            f"{self._base}/clients", json=req.model_dump(exclude_none=True)
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return OAuthClient(**resp.json())

    # ------------------------------------------------------------------
    # Protected endpoints
    # ------------------------------------------------------------------

    def userinfo(self, access_token: Optional[str] = None) -> UserInfoResponse:
        """Retrieve OpenID Connect userinfo."""
        token = access_token or self._token
        if not token:
            raise HearthError(401, "no access token provided")
        resp = self._http.get(
            f"{self._base}/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return UserInfoResponse(**resp.json())

    def permissions(self, access_token: Optional[str] = None) -> MePermissionsResponse:
        """Retrieve the current user's effective permissions."""
        token = access_token or self._token
        if not token:
            raise HearthError(401, "no access token provided")
        resp = self._http.get(
            f"{self._base}/v1/me/permissions",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return MePermissionsResponse(**resp.json())

    def jwks(self) -> JwksDocument:
        """Fetch the JSON Web Key Set document."""
        resp = self._http.get(f"{self._base}/.well-known/jwks.json")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return JwksDocument(**resp.json())

    def discovery(self) -> Dict[str, Any]:
        """Fetch the OIDC discovery document."""
        resp = self._http.get(f"{self._base}/.well-known/openid-configuration")
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    # ------------------------------------------------------------------
    # RBAC predicates (local, no network call)
    # ------------------------------------------------------------------

    @staticmethod
    def has_permission(token: str, permission: str) -> bool:
        """Check whether the JWT contains a specific permission."""
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            perms: List[str] = claims.get("permissions", [])
            return permission in perms
        except Exception:
            return False

    @staticmethod
    def has_role(token: str, role: str) -> bool:
        """Check whether the JWT contains a specific role."""
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            roles: List[str] = claims.get("roles", [])
            return role in roles
        except Exception:
            return False

    @staticmethod
    def in_group(token: str, group_slug: str) -> bool:
        """Check whether the JWT indicates membership in a group."""
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            groups: List[str] = claims.get("groups", [])
            return group_slug in groups
        except Exception:
            return False

    @staticmethod
    def in_org(token: str, org_id: str) -> bool:
        """Check whether the JWT is scoped to a specific organization."""
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            oid: Optional[str] = claims.get("oid")
            return oid == org_id
        except Exception:
            return False

    # ------------------------------------------------------------------
    # WebAuthn
    # ------------------------------------------------------------------

    def webauthn_register_begin(
        self, rp_id: str = "", discoverable: bool = True
    ) -> dict:
        """Start a WebAuthn registration ceremony."""
        body = {"rp_id": rp_id, "discoverable": discoverable}
        resp = self._http.post(f"{self._base}/webauthn/register/begin", json=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    def webauthn_register_complete(
        self,
        client_data_json: str,
        attestation_object: str,
        origin: str,
        discoverable: bool = False,
    ) -> dict:
        """Complete a WebAuthn registration ceremony."""
        body = {
            "client_data_json": client_data_json,
            "attestation_object": attestation_object,
            "origin": origin,
            "discoverable": discoverable,
        }
        resp = self._http.post(f"{self._base}/webauthn/register/complete", json=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    def webauthn_auth_begin(
        self, rp_id: str = "", user_id: Optional[str] = None
    ) -> dict:
        """Start a WebAuthn authentication ceremony."""
        body: dict = {"rp_id": rp_id}
        if user_id:
            body["user_id"] = user_id
        resp = self._http.post(f"{self._base}/webauthn/auth/begin", json=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    def webauthn_auth_complete(
        self,
        credential_id: str,
        client_data_json: str,
        authenticator_data: str,
        signature: str,
        origin: str,
        user_handle: Optional[str] = None,
    ) -> dict:
        """Complete a WebAuthn authentication ceremony."""
        body = {
            "credential_id": credential_id,
            "client_data_json": client_data_json,
            "authenticator_data": authenticator_data,
            "signature": signature,
            "origin": origin,
        }
        if user_handle:
            body["user_handle"] = user_handle
        resp = self._http.post(f"{self._base}/webauthn/auth/complete", json=body)
        if resp.status_code != 200:
            raise HearthError(resp.status_code, resp.text)
        return resp.json()

    def close(self):
        """Close the underlying HTTP client."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
