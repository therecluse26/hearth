"""Tests for HearthClient — spec §1–§3.

Covers: constructor validation, OIDC discovery, verify_token (RS256 + ES256),
claims validation (exp, iss, aud, iat), JWKS key rotation, clock skew
boundaries, and introspection.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from hearth import HearthClient, IntrospectionResult, VerifiedToken
from hearth.errors import (
    ConfigurationError,
    DiscoveryError,
    IntrospectionError,
    TokenAudienceError,
    TokenClaimsError,
    TokenExpiredError,
    TokenIssuerError,
    TokenNotYetValidError,
    TokenVerificationError,
)
from tests.conftest import make_ec_jwt, make_rsa_jwt, mock_http, valid_payload

ISSUER = "https://auth.example.com"
CLIENT_ID = "my-client"


# ---------------------------------------------------------------------------
# §1 Configuration
# ---------------------------------------------------------------------------

class TestConfiguration:
    def test_raises_when_issuer_url_empty(self):
        with pytest.raises(ConfigurationError):
            HearthClient(issuer_url="")

    def test_trailing_slash_stripped(self):
        client = HearthClient(issuer_url="https://example.com/")
        assert client._issuer == "https://example.com"

    def test_all_params_stored(self):
        client = HearthClient(
            issuer_url=ISSUER,
            client_id="cid",
            client_secret="csec",
            jwks_ttl=120,
            introspection_endpoint="https://example.com/introspect",
            http_timeout=5.0,
        )
        assert client._client_id == "cid"
        assert client._client_secret == "csec"
        assert client._jwks_ttl == 120
        assert client._introspection_override == "https://example.com/introspect"


# ---------------------------------------------------------------------------
# §1 OIDC discovery
# ---------------------------------------------------------------------------

class TestOidcDiscovery:
    def test_discovery_fetched_on_first_use(self, rsa_jwk):
        http = mock_http(jwks_doc={"keys": [rsa_jwk]})
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = http

        client._get_discovery()
        assert http.get.call_count >= 1
        called_url = http.get.call_args_list[0][0][0]
        assert ".well-known/openid-configuration" in called_url

    def test_discovery_cached_on_second_call(self, rsa_jwk):
        http = mock_http(jwks_doc={"keys": [rsa_jwk]})
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = http

        doc1 = client._get_discovery()
        doc2 = client._get_discovery()
        assert doc1 is doc2  # same object — no second HTTP call for discovery

    def test_raises_discovery_error_on_network_failure(self):
        client = HearthClient(issuer_url=ISSUER)
        http = MagicMock()
        http.get.side_effect = ConnectionError("refused")
        client._http = http
        with pytest.raises(DiscoveryError):
            client._get_discovery()

    def test_raises_discovery_error_on_missing_jwks_uri(self):
        client = HearthClient(issuer_url=ISSUER)
        http = mock_http(discovery_doc={"issuer": ISSUER})  # no jwks_uri
        client._http = http
        with pytest.raises(DiscoveryError):
            client._get_discovery()


# ---------------------------------------------------------------------------
# §2 verify_token — RS256
# ---------------------------------------------------------------------------

class TestVerifyTokenRS256:
    def test_valid_token_returns_verified_token(self, rsa_private_key, rsa_jwk):
        payload = valid_payload(ISSUER, CLIENT_ID)
        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)

        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        vt = client.verify_token(token)
        assert isinstance(vt, VerifiedToken)
        assert vt.subject == "user-123"
        assert vt.issuer == ISSUER

    def test_invalid_signature_raises(self, rsa_private_key_2, rsa_jwk):
        # Token signed with key-2 but JWKS only has key-1.
        payload = valid_payload(ISSUER, CLIENT_ID)
        token = make_rsa_jwt(rsa_private_key_2, "rsa-1", payload)

        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        with pytest.raises(TokenVerificationError):
            client.verify_token(token)

    def test_unsupported_algorithm_raises(self):
        import jwt
        payload = valid_payload(ISSUER, CLIENT_ID)
        token = jwt.encode(payload, "secret", algorithm="HS256", headers={"kid": "k1"})
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        with pytest.raises(TokenVerificationError, match="unsupported algorithm"):
            client.verify_token(token)


# ---------------------------------------------------------------------------
# §2 verify_token — ES256
# ---------------------------------------------------------------------------

class TestVerifyTokenES256:
    def test_valid_es256_token(self, ec_private_key, ec_jwk):
        payload = valid_payload(ISSUER, CLIENT_ID)
        token = make_ec_jwt(ec_private_key, "ec-1", payload)

        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [ec_jwk]})

        vt = client.verify_token(token)
        assert vt.subject == "user-123"


# ---------------------------------------------------------------------------
# §2 Claims validation
# ---------------------------------------------------------------------------

class TestClaimsValidation:
    def test_expired_token_raises(self, rsa_private_key, rsa_jwk):
        payload = valid_payload(ISSUER, CLIENT_ID)
        payload["exp"] = int(time.time()) - 120  # 2 minutes ago

        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        with pytest.raises(TokenExpiredError):
            client.verify_token(token, clock_skew=0)

    def test_wrong_issuer_raises(self, rsa_private_key, rsa_jwk):
        payload = valid_payload("https://evil.example.com", CLIENT_ID)
        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)

        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        with pytest.raises(TokenIssuerError):
            client.verify_token(token)

    def test_wrong_audience_raises(self, rsa_private_key, rsa_jwk):
        payload = valid_payload(ISSUER, "other-client")
        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)

        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        with pytest.raises(TokenAudienceError):
            client.verify_token(token)

    def test_iat_in_future_raises(self, rsa_private_key, rsa_jwk):
        payload = valid_payload(ISSUER, CLIENT_ID)
        payload["iat"] = int(time.time()) + 300  # 5 minutes in the future

        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        with pytest.raises(TokenClaimsError):
            client.verify_token(token, clock_skew=0)

    def test_nbf_in_future_raises(self, rsa_private_key, rsa_jwk):
        payload = valid_payload(ISSUER, CLIENT_ID)
        payload["nbf"] = int(time.time()) + 300

        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        with pytest.raises(TokenNotYetValidError):
            client.verify_token(token, clock_skew=0)

    def test_no_audience_check_when_client_id_absent(self, rsa_private_key, rsa_jwk):
        payload = valid_payload(ISSUER, "any-client")
        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)

        # No client_id → audience check skipped.
        client = HearthClient(issuer_url=ISSUER)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        vt = client.verify_token(token)
        assert vt.subject == "user-123"


# ---------------------------------------------------------------------------
# §2 Clock skew boundary tests
# ---------------------------------------------------------------------------

class TestClockSkewBoundary:
    def test_token_expired_59s_ago_passes_with_60s_skew(self, rsa_private_key, rsa_jwk):
        payload = valid_payload(ISSUER, CLIENT_ID)
        payload["exp"] = int(time.time()) - 59   # 1 second inside tolerance

        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        # Should NOT raise — within 60s clock skew.
        vt = client.verify_token(token, clock_skew=60)
        assert vt.subject == "user-123"

    def test_token_expired_61s_ago_fails_with_60s_skew(self, rsa_private_key, rsa_jwk):
        payload = valid_payload(ISSUER, CLIENT_ID)
        payload["exp"] = int(time.time()) - 61   # 1 second outside tolerance

        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        with pytest.raises(TokenExpiredError):
            client.verify_token(token, clock_skew=60)

    def test_iat_at_exact_skew_boundary_passes(self, rsa_private_key, rsa_jwk):
        skew = 60
        payload = valid_payload(ISSUER, CLIENT_ID)
        payload["iat"] = int(time.time()) + skew  # exactly at boundary

        token = make_rsa_jwt(rsa_private_key, "rsa-1", payload)
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})

        # At exact boundary, must not raise.
        client.verify_token(token, clock_skew=skew)


# ---------------------------------------------------------------------------
# §2 JWKS key rotation integration test
# ---------------------------------------------------------------------------

class TestJwksKeyRotation:
    def test_transparent_key_rotation(
        self, rsa_private_key, rsa_jwk, rsa_private_key_2, rsa_jwk_2
    ):
        """Simulate a key rotation mid-flight."""
        call_count = {"n": 0}

        def get_side_effect(url, **kw):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.headers = {}
            if "openid-configuration" in url:
                r.json.return_value = {
                    "issuer": ISSUER,
                    "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
                    "introspection_endpoint": f"{ISSUER}/introspect",
                }
            else:
                # First two JWKS fetches return key v1; third returns v2.
                if call_count["n"] < 2:
                    r.json.return_value = {"keys": [rsa_jwk]}
                else:
                    r.json.return_value = {"keys": [rsa_jwk_2]}
                call_count["n"] += 1
            return r

        http = MagicMock()
        http.get.side_effect = get_side_effect
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        client._http = http

        # Step 1: verify with v1 key.
        payload1 = valid_payload(ISSUER, CLIENT_ID)
        token1 = make_rsa_jwt(rsa_private_key, "rsa-1", payload1)
        vt1 = client.verify_token(token1)
        assert vt1.subject == "user-123"

        # Step 2: server rotates to v2 (cache still warm for v1 kid).
        # Now try a token signed with the new key — triggers re-fetch.
        payload2 = valid_payload(ISSUER, CLIENT_ID)
        token2 = make_rsa_jwt(rsa_private_key_2, "rsa-2", payload2)

        # Expire cache to force re-fetch.
        client._jwks._expires_at = 0.0
        vt2 = client.verify_token(token2)
        assert vt2.subject == "user-123"

        # Step 3: old key v1 still works (not discarded after rotation).
        vt1_again = client.verify_token(token1)
        assert vt1_again.subject == "user-123"


# ---------------------------------------------------------------------------
# §3 Introspection
# ---------------------------------------------------------------------------

class TestIntrospect:
    def test_active_token_returns_result(self, rsa_jwk):
        client = HearthClient(
            issuer_url=ISSUER, client_id=CLIENT_ID, client_secret="secret"
        )
        http = mock_http(jwks_doc={"keys": [rsa_jwk]})
        http.post.return_value.json.return_value = {
            "active": True,
            "sub": "user-123",
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "scope": "openid",
            "custom": "value",
        }
        client._http = http

        result = client.introspect("any.token.value")
        assert isinstance(result, IntrospectionResult)
        assert result.active is True
        assert result.sub == "user-123"
        assert result.extra.get("custom") == "value"

    def test_inactive_token(self, rsa_jwk):
        client = HearthClient(
            issuer_url=ISSUER, client_id=CLIENT_ID, client_secret="secret"
        )
        http = mock_http(jwks_doc={"keys": [rsa_jwk]})
        http.post.return_value.json.return_value = {"active": False}
        client._http = http

        result = client.introspect("any.token.value")
        assert result.active is False

    def test_requires_client_credentials(self):
        client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
        with pytest.raises(ConfigurationError):
            client.introspect("any.token.value")

    def test_network_failure_raises_introspection_error(self, rsa_jwk):
        from httpx import HTTPStatusError

        client = HearthClient(
            issuer_url=ISSUER, client_id=CLIENT_ID, client_secret="secret"
        )
        http = mock_http(jwks_doc={"keys": [rsa_jwk]})
        http.post.side_effect = ConnectionError("timeout")
        client._http = http

        with pytest.raises(IntrospectionError):
            client.introspect("any.token.value")

    def test_introspect_uses_override_endpoint(self):
        custom_endpoint = "https://custom.example.com/introspect"
        client = HearthClient(
            issuer_url=ISSUER,
            client_id=CLIENT_ID,
            client_secret="secret",
            introspection_endpoint=custom_endpoint,
        )
        http = MagicMock()
        http.post.return_value.json.return_value = {"active": True, "sub": "u"}
        http.post.return_value.status_code = 200
        http.post.return_value.raise_for_status = MagicMock()
        client._http = http

        client.introspect("tok")
        assert http.post.call_args[0][0] == custom_endpoint

    def test_to_verified_token_from_introspection(self, rsa_jwk):
        client = HearthClient(
            issuer_url=ISSUER, client_id=CLIENT_ID, client_secret="secret"
        )
        http = mock_http(jwks_doc={"keys": [rsa_jwk]})
        http.post.return_value.json.return_value = {
            "active": True,
            "sub": "user-456",
            "iss": ISSUER,
            "scope": "openid admin",
            "roles": ["editor"],
        }
        client._http = http

        result = client.introspect("tok")
        vt = result.to_verified_token()
        assert vt.subject == "user-456"
        assert vt.has_scope("admin")
        assert vt.has_role("editor")


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

class TestContextManager:
    def test_close_called_on_exit(self, rsa_jwk):
        http = mock_http(jwks_doc={"keys": [rsa_jwk]})
        with HearthClient(issuer_url=ISSUER) as client:
            client._http = http
        http.close.assert_called()
