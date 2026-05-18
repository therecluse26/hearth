"""Hearth SDK error hierarchy — spec §5."""

from typing import Optional, List


class HearthError(Exception):
    """Raised when the Hearth API returns an error response."""

    def __init__(self, status_code: int, message: str, details: Optional[dict] = None):
        self.status_code = status_code
        self.message = message
        self.details = details
        super().__init__(f"HTTP {status_code}: {message}")


class HearthSdkError(Exception):
    """Base class for all Hearth SDK client-side errors (spec §5)."""


class ConfigurationError(HearthSdkError):
    """Raised when the client is misconfigured (missing base_url, realm_id, etc.)."""

    def __init__(self, message: str, field: Optional[str] = None):
        self.field = field
        prefix = f"configuration error ({field}): " if field else "configuration error: "
        super().__init__(prefix + message)


class DiscoveryError(HearthSdkError):
    """Raised when the OIDC discovery document cannot be fetched or parsed."""

    def __init__(self, message: str, url: Optional[str] = None, cause: Optional[Exception] = None):
        self.url = url
        self.cause = cause
        super().__init__(message)


class JWKSFetchError(HearthSdkError):
    """Raised when the JWKS document cannot be retrieved or parsed."""

    def __init__(self, message: str, url: Optional[str] = None, cause: Optional[Exception] = None):
        self.url = url
        self.cause = cause
        super().__init__(message)


class TokenExpiredError(HearthSdkError):
    """Raised when a token's exp claim is in the past."""

    def __init__(self, expired_at: int, message: Optional[str] = None):
        self.expired_at = expired_at
        super().__init__(message or f"Token expired at unix={expired_at}")


class TokenNotYetValidError(HearthSdkError):
    """Raised when a token's nbf claim is in the future."""

    def __init__(self, not_before: int, message: Optional[str] = None):
        self.not_before = not_before
        super().__init__(message or f"Token not yet valid until unix={not_before}")


class TokenInvalidError(HearthSdkError):
    """Raised when a token fails structural or signature validation."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__("Token invalid: " + reason)


class TokenIssuerError(HearthSdkError):
    """Raised when the token's iss claim does not match the expected issuer."""

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(f'Token issuer mismatch: expected "{expected}", got "{actual}"')


class TokenAudienceError(HearthSdkError):
    """Raised when the token's aud claim does not include the expected audience."""

    def __init__(self, expected: str, actual: List[str]):
        self.expected = expected
        self.actual = actual
        super().__init__(f'Token audience mismatch: expected "{expected}", got {actual}')


class IntrospectionError(HearthSdkError):
    """Raised when a token introspection request fails or returns inactive."""

    def __init__(self, message: str, cause: Optional[Exception] = None):
        self.cause = cause
        super().__init__(message)
