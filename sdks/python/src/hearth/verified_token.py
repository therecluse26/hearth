"""Spec §4 — VerifiedToken.

Wraps a verified JWT payload with typed, snake_case accessors.
All comparisons in ``has_scope``, ``has_role``, and ``has_permission``
use ``hmac.compare_digest`` for timing safety (spec §11).
"""
from __future__ import annotations

import hmac
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _safe_eq(a: str, b: str) -> bool:
    """Timing-safe string equality (spec §11)."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class VerifiedToken:
    """Typed accessor for a verified JWT's claims (spec §4).

    Constructed by :meth:`HearthClient.verify_token` after full signature
    and claims validation.  All reads are local — no network call is made.
    """

    def __init__(self, payload: Dict[str, Any]) -> None:
        self._payload = payload

    # ------------------------------------------------------------------
    # Standard OIDC accessors
    # ------------------------------------------------------------------

    @property
    def subject(self) -> str:
        """Return the ``sub`` claim."""
        return str(self._payload.get("sub", ""))

    @property
    def issuer(self) -> str:
        """Return the ``iss`` claim."""
        return str(self._payload.get("iss", ""))

    @property
    def audience(self) -> List[str]:
        """Return the ``aud`` claim normalised to a list."""
        aud = self._payload.get("aud")
        if aud is None:
            return []
        return [str(a) for a in aud] if isinstance(aud, list) else [str(aud)]

    @property
    def issued_at(self) -> Optional[datetime]:
        """Return the ``iat`` claim as a UTC datetime, or ``None``."""
        val = self._payload.get("iat")
        if val is None:
            return None
        return datetime.fromtimestamp(int(val), tz=timezone.utc)

    @property
    def expires_at(self) -> Optional[datetime]:
        """Return the ``exp`` claim as a UTC datetime, or ``None``."""
        val = self._payload.get("exp")
        if val is None:
            return None
        return datetime.fromtimestamp(int(val), tz=timezone.utc)

    @property
    def not_before(self) -> Optional[datetime]:
        """Return the ``nbf`` claim as a UTC datetime, or ``None``."""
        val = self._payload.get("nbf")
        if val is None:
            return None
        return datetime.fromtimestamp(int(val), tz=timezone.utc)

    @property
    def scope(self) -> str:
        """Return the ``scope`` claim as a space-delimited string."""
        return str(self._payload.get("scope", ""))

    @property
    def scopes(self) -> List[str]:
        """Return the individual scopes parsed from the ``scope`` claim."""
        raw = self.scope
        return [s for s in raw.split() if s] if raw else []

    @property
    def raw(self) -> Dict[str, Any]:
        """Return a copy of the raw payload dict."""
        return dict(self._payload)

    def get(self, key: str) -> Any:
        """Return an arbitrary claim by key."""
        return self._payload.get(key)

    # ------------------------------------------------------------------
    # Hearth-specific helpers — timing-safe (spec §4, §11)
    # ------------------------------------------------------------------

    def has_scope(self, s: str) -> bool:
        """Return ``True`` iff the token's ``scope`` claim contains ``s``."""
        return any(_safe_eq(scope, s) for scope in self.scopes)

    def has_role(self, r: str) -> bool:
        """Return ``True`` iff the Hearth ``roles`` claim contains ``r``."""
        roles: List[str] = self._payload.get("roles") or []
        return any(_safe_eq(role, r) for role in roles)

    def has_permission(self, p: str) -> bool:
        """Return ``True`` iff the Hearth ``permissions`` claim contains ``p``."""
        perms: List[str] = self._payload.get("permissions") or []
        return any(_safe_eq(perm, p) for perm in perms)

    def __repr__(self) -> str:
        return f"VerifiedToken(sub={self.subject!r})"
