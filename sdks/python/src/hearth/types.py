"""Hearth API request and response types."""
from __future__ import annotations

from typing import Any, Dict, Generic, List, Optional, TypeVar, Union

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class BootstrapResponse(BaseModel):
    admin_token: str
    realm_id: str
    user_id: str
    access_token: str
    refresh_token: str


class User(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    status: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class CreateUserRequest(BaseModel):
    username: str
    email: Optional[str] = None
    password: Optional[str] = None
    attributes: Optional[dict] = None


class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None
    attributes: Optional[dict] = None


class PageResponse(BaseModel, Generic[T]):
    items: List[T]
    next_cursor: Optional[str] = None
    total: Optional[int] = None


class Realm(BaseModel):
    id: str
    name: str
    status: str
    config: Optional[dict] = None
    created_at: Optional[str] = None


class CreateRealmRequest(BaseModel):
    name: str
    config: Optional[dict] = None


class UpdateRealmRequest(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None
    status: Optional[str] = None


class AuthorizeResponse(BaseModel):
    code: str
    state: str
    redirect_uri: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    scope: Optional[str] = None
    id_token: Optional[str] = None


class UserInfoResponse(BaseModel):
    sub: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    preferred_username: Optional[str] = None
    permissions: Optional[List[str]] = None
    roles: Optional[List[str]] = None
    groups: Optional[List[str]] = None


class MePermissionsResponse(BaseModel):
    permissions: List[str]
    roles: List[str]
    groups: List[str]


class OAuthClient(BaseModel):
    id: str
    name: str
    redirect_uris: List[str] = []
    trust_level: Optional[str] = None
    secret: Optional[str] = None


class RegisterClientRequest(BaseModel):
    name: str
    redirect_uris: List[str] = []
    trust_level: Optional[str] = None


class Jwk(BaseModel):
    """JSON Web Key — supports both RSA and EC key types."""

    model_config = ConfigDict(extra="allow")

    kty: str
    kid: Optional[str] = None
    use: Optional[str] = None
    alg: Optional[str] = None
    # EC fields
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None
    # RSA fields
    n: Optional[str] = None
    e: Optional[str] = None


class JwksDocument(BaseModel):
    keys: List[Jwk]


# ---------------------------------------------------------------------------
# §3 Token Introspection (RFC 7662)
# ---------------------------------------------------------------------------

_INTROSPECTION_STANDARD_FIELDS = frozenset(
    {"active", "sub", "iss", "aud", "exp", "iat", "scope", "client_id",
     "username", "token_type", "jti"}
)


class IntrospectionResult(BaseModel):
    """RFC 7662 token introspection response (spec §3).

    Non-standard claims are collected in ``extra``.
    Results must never be cached (RFC 7662 §2.1).
    """

    active: bool
    sub: Optional[str] = None
    iss: Optional[str] = None
    aud: Optional[Union[str, List[str]]] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    scope: Optional[str] = None
    client_id: Optional[str] = None
    extra: Dict[str, Any] = {}

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "IntrospectionResult":
        extra = {k: v for k, v in data.items() if k not in _INTROSPECTION_STANDARD_FIELDS}
        return cls(
            active=bool(data.get("active", False)),
            sub=data.get("sub"),
            iss=data.get("iss"),
            aud=data.get("aud"),
            exp=data.get("exp"),
            iat=data.get("iat"),
            scope=data.get("scope"),
            client_id=data.get("client_id"),
            extra=extra,
        )

    def to_verified_token(self) -> "VerifiedToken":
        """Construct a :class:`VerifiedToken` from introspection claims."""
        from .verified_token import VerifiedToken

        payload: Dict[str, Any] = {}
        if self.sub is not None:
            payload["sub"] = self.sub
        if self.iss is not None:
            payload["iss"] = self.iss
        if self.aud is not None:
            payload["aud"] = self.aud
        if self.exp is not None:
            payload["exp"] = self.exp
        if self.iat is not None:
            payload["iat"] = self.iat
        if self.scope is not None:
            payload["scope"] = self.scope
        payload.update(self.extra)
        return VerifiedToken(payload)
