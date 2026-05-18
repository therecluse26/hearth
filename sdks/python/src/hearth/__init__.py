"""Hearth identity platform Python SDK.

Provides HearthClient (auth flows, RBAC predicates), AdminClient
(user/realm CRUD), and all request/response types.
"""

from .client import HearthClient
from .admin import AdminClient
from .errors import (
    HearthError,
    HearthSdkError,
    ConfigurationError,
    DiscoveryError,
    JWKSFetchError,
    TokenExpiredError,
    TokenNotYetValidError,
    TokenInvalidError,
    TokenIssuerError,
    TokenAudienceError,
    IntrospectionError,
)
from .claims import Claims
from .types import (
    BootstrapResponse,
    User,
    CreateUserRequest,
    UpdateUserRequest,
    Realm,
    CreateRealmRequest,
    UpdateRealmRequest,
    PageResponse,
    AuthorizeResponse,
    TokenResponse,
    UserInfoResponse,
    MePermissionsResponse,
    OAuthClient,
    RegisterClientRequest,
    JwksDocument,
)

__all__ = [
    "HearthClient",
    "AdminClient",
    "HearthError",
    "HearthSdkError",
    "ConfigurationError",
    "DiscoveryError",
    "JWKSFetchError",
    "TokenExpiredError",
    "TokenNotYetValidError",
    "TokenInvalidError",
    "TokenIssuerError",
    "TokenAudienceError",
    "IntrospectionError",
    "Claims",
    "BootstrapResponse",
    "User",
    "CreateUserRequest",
    "UpdateUserRequest",
    "Realm",
    "CreateRealmRequest",
    "UpdateRealmRequest",
    "PageResponse",
    "AuthorizeResponse",
    "TokenResponse",
    "UserInfoResponse",
    "MePermissionsResponse",
    "OAuthClient",
    "RegisterClientRequest",
    "JwksDocument",
]
