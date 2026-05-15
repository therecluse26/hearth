"""Hearth identity platform Python SDK.

Provides :class:`HearthClient` (token verification, introspection, OAuth
flows), :class:`AdminClient` (user/realm CRUD), typed claims via
:class:`VerifiedToken`, and all required error types.
"""

from .client import HearthClient
from .admin import AdminClient
from .verified_token import VerifiedToken
from .errors import (
    HearthError,
    ConfigurationError,
    DiscoveryError,
    JwksFetchError,
    JWKSFetchError,         # uppercase alias for spec conformance checklist
    TokenVerificationError,
    TokenInvalidError,      # alias for TokenVerificationError
    TokenExpiredError,
    TokenClaimsError,
    TokenIssuerError,
    TokenAudienceError,
    TokenNotYetValidError,
    IntrospectionError,
    MiddlewareError,
)
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
    IntrospectionResult,
)

__all__ = [
    # Clients
    "HearthClient",
    "AdminClient",
    # Claims
    "VerifiedToken",
    # Errors — 9 spec types
    "HearthError",
    "ConfigurationError",
    "DiscoveryError",
    "JwksFetchError",
    "JWKSFetchError",
    "TokenVerificationError",
    "TokenInvalidError",
    "TokenExpiredError",
    "TokenClaimsError",
    "TokenIssuerError",
    "TokenAudienceError",
    "TokenNotYetValidError",
    "IntrospectionError",
    "MiddlewareError",
    # Types
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
    "IntrospectionResult",
]
