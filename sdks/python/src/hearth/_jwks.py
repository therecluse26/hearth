"""Internal JWKS cache — spec §2 caching rules 1–5.

Rules:
  1. Cache keys by ``kid``. Never discard keys absent from the latest fetch.
  2. Respect ``Cache-Control: max-age`` from the JWKS response.
  3. On cache miss for a ``kid``: re-fetch once before returning an error.
  4. (Caller responsibility) On HTTP 401 from a protected resource: call
     :meth:`force_refresh` then retry.
  5. Maximum cache age: 24 hours regardless of ``Cache-Control``.
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any, Dict, Optional

import httpx

from .errors import JwksFetchError, TokenVerificationError

_DEFAULT_TTL_S: int = 300   # 5 minutes
_MAX_TTL_S: int = 86_400    # 24 hours


def _parse_max_age(header: str) -> Optional[int]:
    m = re.search(r"max-age=(\d+)", header, re.IGNORECASE)
    return int(m.group(1)) if m else None


class JwksCache:
    """Thread-safe JWKS key cache (spec §2 rules 1–5).

    Keys are stored by ``kid`` and **never** evicted — only added or
    updated.  This allows in-flight tokens signed with a recently rotated
    key to continue verifying during the overlap window.
    """

    def __init__(
        self,
        jwks_uri: str,
        http: httpx.Client,
        override_ttl: Optional[int] = None,
    ) -> None:
        self._uri = jwks_uri
        self._http = http
        self._override_ttl = override_ttl
        self._lock = threading.Lock()
        self._keys: Dict[str, Any] = {}   # kid -> decoded public-key object
        self._expires_at: float = 0.0     # monotonic clock

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_key(self, kid: str) -> Any:
        """Return the public key for *kid*, fetching JWKS if necessary.

        Behaviour:
        - If the cache is stale, refresh then look up.
        - If *kid* is still missing after refresh, raise
          :class:`TokenVerificationError`.
        - If the cache is fresh but *kid* is absent, re-fetch once
          (rule 3) then raise if still missing.

        :raises JwksFetchError: when the JWKS endpoint is unreachable.
        :raises TokenVerificationError: when *kid* is not found after fetch.
        """
        with self._lock:
            now = time.monotonic()
            if now >= self._expires_at:
                # Cache stale — full refresh.
                self._fetch_locked()

            if kid in self._keys:
                return self._keys[kid]

            # Cache is fresh but kid is unknown — re-fetch once (rule 3).
            self._fetch_locked()
            if kid in self._keys:
                return self._keys[kid]

        raise TokenVerificationError(f"no JWKS key found for kid={kid!r}")

    def force_refresh(self) -> None:
        """Force an immediate JWKS re-fetch (rule 4: called after HTTP 401)."""
        with self._lock:
            self._fetch_locked()

    # ------------------------------------------------------------------
    # Internal helpers (must be called with _lock held)
    # ------------------------------------------------------------------

    def _fetch_locked(self) -> None:
        try:
            resp = self._http.get(self._uri)
            resp.raise_for_status()
        except Exception as exc:
            raise JwksFetchError(
                f"JWKS endpoint unavailable: {type(exc).__name__}", url=self._uri
            ) from exc

        try:
            doc: Dict[str, Any] = resp.json()
        except Exception as exc:
            raise JwksFetchError("JWKS response is not valid JSON", url=self._uri) from exc

        self._import_keys(doc)

        if self._override_ttl is not None:
            ttl = min(self._override_ttl, _MAX_TTL_S)
        else:
            max_age = _parse_max_age(resp.headers.get("cache-control", ""))
            ttl = min(max_age if max_age is not None else _DEFAULT_TTL_S, _MAX_TTL_S)

        self._expires_at = time.monotonic() + ttl

    def _import_keys(self, doc: Dict[str, Any]) -> None:
        """Merge new keys into the cache without discarding existing ones (rule 1)."""
        # Import lazily to avoid hard-coupling PyJWT internals at module load.
        try:
            from jwt.algorithms import ECAlgorithm, RSAAlgorithm
        except ImportError as exc:
            raise JwksFetchError(
                "pyjwt[crypto] is required for JWKS key import"
            ) from exc

        for jwk in doc.get("keys", []):
            kid = jwk.get("kid")
            kty = str(jwk.get("kty", ""))
            if not kid:
                continue
            try:
                jwk_str = json.dumps(jwk)
                if kty == "RSA":
                    self._keys[kid] = RSAAlgorithm.from_jwk(jwk_str)
                elif kty == "EC":
                    self._keys[kid] = ECAlgorithm.from_jwk(jwk_str)
                # Other key types ignored; not supported per spec §2.
            except Exception:
                pass  # Unparseable key — skip; don't crash the cache refresh.
