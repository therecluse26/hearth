"""Hearth API request and response types."""

from typing import Optional, List, Any, Generic, TypeVar

from pydantic import BaseModel

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
    kty: str
    crv: str
    x: str
    kid: str
    use: str
    alg: str


class JwksDocument(BaseModel):
    keys: List[Jwk]
