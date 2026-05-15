"""Hearth SDK error hierarchy — spec §5.

All 9 required exception types. Messages never include raw tokens or
secrets (spec §11). Cause-chaining via standard ``raise … from exc``
exposes the underlying exception as ``__cause__``.
"""
from __future__ import annotations

from typing import List, Optional


class HearthError(Exception):
    """Root exception for all Hearth SDK errors.

    Subclass for every typed failure path; catch this to handle any
    Hearth-SDK error in one place.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConfigurationError(HearthError):
    """Client is misconfigured (missing required field, invalid URL, etc.)."""

    def __init__(self, message: str, field: Optional[str] = None) -> None:
        self.field = field
        prefix = f"[{field}] " if field else ""
        super().__init__(f"ConfigurationError: {prefix}{message}")


class DiscoveryError(HearthError):
    """OIDC discovery document unreachable or returned invalid JSON."""

    def __init__(self, message: str, url: Optional[str] = None) -> None:
        self.url = url
        super().__init__(f"DiscoveryError: {message}")


class JwksFetchError(HearthError):
    """JWKS endpoint unreachable or returned an invalid response."""

    def __init__(self, message: str, url: Optional[str] = None) -> None:
        self.url = url
        super().__init__(f"JwksFetchError: {message}")


# Uppercase alias kept for spec conformance checklist.
JWKSFetchError = JwksFetchError


class TokenVerificationError(HearthError):
    """Token signature invalid, JWT malformed, or algorithm not supported."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"TokenVerificationError: {reason}")


# Alias used internally and by pre-existing callers.
TokenInvalidError = TokenVerificationError


class TokenExpiredError(HearthError):
    """Token's ``exp`` claim is in the past (beyond clock-skew tolerance)."""

    def __init__(self, expired_at: int, message: Optional[str] = None) -> None:
        self.expired_at = expired_at
        super().__init__(message or "TokenExpiredError: token has expired")


class TokenClaimsError(HearthError):
    """A required JWT claim (``iss``, ``aud``, ``nbf``) failed validation."""

    def __init__(self, message: str) -> None:
        super().__init__(f"TokenClaimsError: {message}")


class TokenIssuerError(TokenClaimsError):
    """``iss`` claim does not match the configured issuer."""

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__("issuer mismatch")


class TokenAudienceError(TokenClaimsError):
    """``aud`` claim does not contain the expected audience."""

    def __init__(self, expected: str, actual: List[str]) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__("audience mismatch")


class TokenNotYetValidError(TokenClaimsError):
    """``nbf`` claim is in the future (beyond clock-skew tolerance)."""

    def __init__(self, not_before: int) -> None:
        self.not_before = not_before
        super().__init__("token not yet valid")


class IntrospectionError(HearthError):
    """Introspection endpoint unreachable or returned an error."""

    def __init__(self, message: str) -> None:
        super().__init__(f"IntrospectionError: {message}")


class MiddlewareError(HearthError):
    """An error occurred within the Hearth HTTP middleware."""

    def __init__(self, message: str) -> None:
        super().__init__(f"MiddlewareError: {message}")
