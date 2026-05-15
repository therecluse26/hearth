"""Spec §4 — Claims API.

:class:`Claims` wraps a decoded JWT payload and exposes typed accessors
for standard OIDC and Hearth-specific claims.  All reads are local —
no network call is made.  Signature verification is the caller's
responsibility.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List, Optional, Union

from .errors import (
    TokenExpiredError,
    TokenInvalidError,
    TokenNotYetValidError,
)


class Claims:
    """Typed accessor for a decoded JWT's claims (spec §4).

    Construct via :meth:`decode` or pass a pre-decoded payload dict.
    """

    def __init__(self, payload: Dict[str, Any]) -> None:
        self._payload = payload

    @classmethod
    def decode(cls, token: str) -> "Claims":
        """Decode a JWT string without verifying its signature.

        :raises TokenInvalidError: if the string is not a structurally valid JWT.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenInvalidError("expected three dot-separated segments")
        try:
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            payload_bytes = base64.urlsafe_b64decode(padded)
            payload: Dict[str, Any] = json.loads(payload_bytes)
        except Exception as exc:
            raise TokenInvalidError(f"failed to decode JWT payload: {exc}") from exc
        return cls(payload)

    def assert_valid(self, clock_skew_seconds: int = 0) -> None:
        """Assert the token is temporally valid.

        :raises TokenExpiredError: if exp is in the past.
        :raises TokenNotYetValidError: if nbf is in the future.
        """
        now = int(time.time())
        exp = self._payload.get("exp")
        if exp is not None and now > exp + clock_skew_seconds:
            raise TokenExpiredError(exp)
        nbf = self._payload.get("nbf")
        if nbf is not None and now < nbf - clock_skew_seconds:
            raise TokenNotYetValidError(nbf)

    def subject(self) -> str:
        """Return the ``sub`` (subject) claim."""
        return str(self._payload.get("sub", ""))

    def issuer(self) -> str:
        """Return the ``iss`` (issuer) claim."""
        return str(self._payload.get("iss", ""))

    def audiences(self) -> List[str]:
        """Return the ``aud`` (audiences) claim normalised to a list."""
        aud = self._payload.get("aud")
        if aud is None:
            return []
        if isinstance(aud, list):
            return [str(a) for a in aud]
        return [str(aud)]

    def expiry(self) -> Optional[int]:
        """Return the ``exp`` claim as a Unix timestamp, or None if absent."""
        val = self._payload.get("exp")
        return int(val) if val is not None else None

    def issuedAt(self) -> Optional[int]:
        """Return the ``iat`` claim as a Unix timestamp, or None if absent."""
        val = self._payload.get("iat")
        return int(val) if val is not None else None

    def jwtID(self) -> Optional[str]:
        """Return the ``jti`` (JWT ID) claim, or None if absent."""
        val = self._payload.get("jti")
        return str(val) if val is not None else None

    def scopes(self) -> List[str]:
        """Return the individual scopes from the ``scope`` claim."""
        raw = self._payload.get("scope", "")
        if not raw:
            return []
        return [s for s in str(raw).split() if s]

    def hasScope(self, scope: str) -> bool:
        """Return True iff the token contains the given scope."""
        return scope in self.scopes()

    def hasRole(self, role: str) -> bool:
        """Return True iff the token's ``roles`` claim contains the given role."""
        roles: List[str] = self._payload.get("roles", [])
        return role in roles

    def hasPermission(self, permission: str) -> bool:
        """Return True iff the token's ``permissions`` claim contains the given permission."""
        permissions: List[str] = self._payload.get("permissions", [])
        return permission in permissions

    def get(self, key: str) -> Any:
        """Return an arbitrary claim by key."""
        return self._payload.get(key)

    def __repr__(self) -> str:
        return f"Claims(sub={self.subject()!r}, iss={self.issuer()!r})"
