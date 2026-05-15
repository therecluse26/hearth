"""Tests for spec §2 JWKS caching — all 5 rules.

Rule 1: Cache keys by kid; don't discard absent keys after a fetch.
Rule 2: Respect Cache-Control: max-age from the JWKS endpoint.
Rule 3: On cache miss for a kid: re-fetch once before returning error.
Rule 4: (External) On HTTP 401: force_refresh then retry.
Rule 5: Maximum cache age 24 h regardless of Cache-Control.
"""
from __future__ import annotations

import json
import time
from unittest.mock import MagicMock

import pytest

from hearth._jwks import JwksCache, _MAX_TTL_S, _DEFAULT_TTL_S
from hearth.errors import JwksFetchError, TokenVerificationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jwks_response(keys, max_age=None, status=200):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = {"keys": keys}
    r.headers = {"cache-control": f"max-age={max_age}"} if max_age else {}
    if status >= 400:
        from httpx import HTTPStatusError
        r.raise_for_status.side_effect = HTTPStatusError(
            str(status), request=MagicMock(), response=r
        )
    else:
        r.raise_for_status = MagicMock()
    return r


def _build_jwks_cache(responses, override_ttl=None):
    http = MagicMock()
    http.get.side_effect = responses
    return JwksCache(
        jwks_uri="https://auth.example.com/.well-known/jwks.json",
        http=http,
        override_ttl=override_ttl,
    )


# ---------------------------------------------------------------------------
# Rule 1: No key discard
# ---------------------------------------------------------------------------

class TestRule1NoKeyDiscard:
    def test_old_kid_retained_after_key_rotation(self, rsa_jwk, rsa_jwk_2):
        jwks_v1 = {"keys": [rsa_jwk]}
        jwks_v2 = {"keys": [rsa_jwk_2]}

        call_count = {"n": 0}

        def responses(url, **kw):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.headers = {}
            if call_count["n"] == 0:
                r.json.return_value = jwks_v1
            else:
                r.json.return_value = jwks_v2
            call_count["n"] += 1
            return r

        cache = JwksCache("https://auth.example.com/.well-known/jwks.json", MagicMock())
        cache._http.get.side_effect = responses

        # Prime the cache with key v1.
        cache.get_key("rsa-1")
        # Force a re-fetch that returns only v2.
        cache.force_refresh()

        # Both keys should now be available.
        cache.get_key("rsa-1")   # old key still there
        cache.get_key("rsa-2")   # new key added


# ---------------------------------------------------------------------------
# Rule 2: Cache-Control max-age
# ---------------------------------------------------------------------------

class TestRule2CacheControlMaxAge:
    def test_respects_max_age_from_header(self, rsa_jwk):
        http = MagicMock()
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.headers = {"cache-control": "max-age=300"}
        r.json.return_value = {"keys": [rsa_jwk]}
        http.get.return_value = r

        cache = JwksCache("https://example.com/jwks", http)
        cache.get_key("rsa-1")

        # Should only have fetched once; cache is warm.
        http.get.assert_called_once()

    def test_falls_back_to_default_ttl_when_no_cache_control(self, rsa_jwk):
        http = MagicMock()
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.headers = {}
        r.json.return_value = {"keys": [rsa_jwk]}
        http.get.return_value = r

        cache = JwksCache("https://example.com/jwks", http)
        # Set expiry to past to force re-fetch.
        cache._expires_at = time.monotonic() - 1
        cache.get_key("rsa-1")
        assert cache._expires_at > time.monotonic()


# ---------------------------------------------------------------------------
# Rule 3: Re-fetch on kid cache miss
# ---------------------------------------------------------------------------

class TestRule3RefetchOnKidMiss:
    def test_refetches_when_kid_unknown(self, rsa_jwk):
        http = MagicMock()
        first = MagicMock()
        first.raise_for_status = MagicMock()
        first.headers = {}
        first.json.return_value = {"keys": []}  # no keys first

        second = MagicMock()
        second.raise_for_status = MagicMock()
        second.headers = {}
        second.json.return_value = {"keys": [rsa_jwk]}  # key appears after re-fetch

        http.get.side_effect = [first, second]
        cache = JwksCache("https://example.com/jwks", http)
        key = cache.get_key("rsa-1")
        assert key is not None
        assert http.get.call_count == 2

    def test_raises_token_verification_error_when_kid_still_unknown(self):
        http = MagicMock()
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.headers = {}
        r.json.return_value = {"keys": []}
        http.get.return_value = r

        cache = JwksCache("https://example.com/jwks", http)
        with pytest.raises(TokenVerificationError):
            cache.get_key("unknown-kid")


# ---------------------------------------------------------------------------
# Rule 5: 24-hour cap
# ---------------------------------------------------------------------------

class TestRule5MaxTTLCap:
    def test_max_age_capped_at_24h(self, rsa_jwk):
        http = MagicMock()
        r = MagicMock()
        r.raise_for_status = MagicMock()
        # Server advertises 48h — must be capped to 24h.
        r.headers = {"cache-control": "max-age=172800"}
        r.json.return_value = {"keys": [rsa_jwk]}
        http.get.return_value = r

        cache = JwksCache("https://example.com/jwks", http)
        before = time.monotonic()
        cache.get_key("rsa-1")
        after = time.monotonic()

        elapsed = cache._expires_at - before
        assert elapsed <= _MAX_TTL_S + 1

    def test_override_ttl_is_also_capped(self, rsa_jwk):
        http = MagicMock()
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.headers = {}
        r.json.return_value = {"keys": [rsa_jwk]}
        http.get.return_value = r

        cache = JwksCache("https://example.com/jwks", http, override_ttl=999999)
        cache.get_key("rsa-1")
        elapsed = cache._expires_at - time.monotonic()
        assert elapsed <= _MAX_TTL_S + 1


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

class TestJwksFetchErrors:
    def test_raises_jwks_fetch_error_on_network_failure(self):
        http = MagicMock()
        http.get.side_effect = ConnectionError("timeout")
        cache = JwksCache("https://example.com/jwks", http)
        with pytest.raises(JwksFetchError):
            cache.get_key("rsa-1")

    def test_raises_jwks_fetch_error_on_bad_json(self):
        http = MagicMock()
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.headers = {}
        r.json.side_effect = ValueError("not json")
        http.get.return_value = r
        cache = JwksCache("https://example.com/jwks", http)
        with pytest.raises(JwksFetchError):
            cache.get_key("rsa-1")


# ---------------------------------------------------------------------------
# force_refresh (rule 4 helper)
# ---------------------------------------------------------------------------

class TestForceRefresh:
    def test_force_refresh_fetches_new_keys(self, rsa_jwk_2):
        http = MagicMock()
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.headers = {}
        r.json.return_value = {"keys": [rsa_jwk_2]}
        http.get.return_value = r

        cache = JwksCache("https://example.com/jwks", http)
        cache.force_refresh()
        assert "rsa-2" in cache._keys
