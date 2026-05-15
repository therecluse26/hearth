"""Tests for HearthClient OAuth flows and JWKS direct fetch."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from hearth import HearthClient
from hearth.errors import ConfigurationError, HearthError, JwksFetchError
from tests.conftest import mock_http

ISSUER = "https://auth.example.com"
CLIENT_ID = "my-client"
SECRET = "my-secret"


def _client(rsa_jwk=None):
    c = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID, client_secret=SECRET)
    c._http = mock_http(jwks_doc={"keys": [rsa_jwk]} if rsa_jwk else {"keys": []})
    return c


def _post_response(json_body, status=200):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = json_body
    r.raise_for_status = MagicMock()
    return r


class TestAuthorize:
    def test_authorize_returns_response(self, rsa_jwk):
        c = _client(rsa_jwk)
        c._http.get.side_effect = None  # reset side_effect
        disc_resp = MagicMock()
        disc_resp.status_code = 200
        disc_resp.raise_for_status = MagicMock()
        disc_resp.headers = {}
        disc_resp.json.return_value = {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        }
        auth_resp = MagicMock()
        auth_resp.status_code = 200
        auth_resp.json.return_value = {"code": "abc", "state": "xyz"}
        c._http.get.side_effect = [disc_resp, auth_resp]

        result = c.authorize(redirect_uri="https://app.example.com/cb", state="xyz")
        assert result.code == "abc"

    def test_authorize_without_client_id_raises(self):
        c = HearthClient(issuer_url=ISSUER)
        with pytest.raises(ConfigurationError, match="client_id"):
            c.authorize(redirect_uri="https://cb.example.com")


class TestExchangeCode:
    def test_exchange_code_returns_token(self, rsa_jwk):
        c = _client(rsa_jwk)
        c._http.get.side_effect = None
        disc_resp = MagicMock()
        disc_resp.status_code = 200
        disc_resp.raise_for_status = MagicMock()
        disc_resp.headers = {}
        disc_resp.json.return_value = {
            "issuer": ISSUER,
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        }
        c._http.get.return_value = disc_resp
        c._http.post.return_value = _post_response({
            "access_token": "at",
            "refresh_token": "rt",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

        result = c.exchange_code(code="code-123", redirect_uri="https://cb.example.com")
        assert result.access_token == "at"

    def test_exchange_code_without_client_id_raises(self):
        c = HearthClient(issuer_url=ISSUER)
        with pytest.raises(ConfigurationError):
            c.exchange_code(code="c", redirect_uri="https://cb.example.com")


class TestRefreshTokens:
    def test_refresh_returns_token(self, rsa_jwk):
        c = _client(rsa_jwk)
        disc_resp = MagicMock()
        disc_resp.status_code = 200
        disc_resp.raise_for_status = MagicMock()
        disc_resp.headers = {}
        disc_resp.json.return_value = {
            "issuer": ISSUER,
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        }
        c._http.get.return_value = disc_resp
        c._http.post.return_value = _post_response({
            "access_token": "new-at",
            "refresh_token": "new-rt",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

        result = c.refresh_tokens("old-rt")
        assert result.access_token == "new-at"

    def test_refresh_without_client_id_raises(self):
        c = HearthClient(issuer_url=ISSUER)
        with pytest.raises(ConfigurationError):
            c.refresh_tokens("rt")


class TestUserinfo:
    def test_userinfo_returns_response(self, rsa_jwk):
        c = _client(rsa_jwk)
        disc_resp = MagicMock()
        disc_resp.status_code = 200
        disc_resp.raise_for_status = MagicMock()
        disc_resp.headers = {}
        disc_resp.json.return_value = {
            "issuer": ISSUER,
            "userinfo_endpoint": f"{ISSUER}/userinfo",
            "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        }
        userinfo_resp = MagicMock()
        userinfo_resp.status_code = 200
        userinfo_resp.json.return_value = {"sub": "user-123"}
        c._http.get.side_effect = [disc_resp, userinfo_resp]

        result = c.userinfo("at-value")
        assert result.sub == "user-123"

    def test_userinfo_401_triggers_jwks_refresh(self, rsa_jwk):
        c = _client(rsa_jwk)
        disc_resp = MagicMock()
        disc_resp.status_code = 200
        disc_resp.raise_for_status = MagicMock()
        disc_resp.headers = {}
        disc_resp.json.return_value = {
            "issuer": ISSUER,
            "userinfo_endpoint": f"{ISSUER}/userinfo",
            "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        }
        unauth_resp = MagicMock()
        unauth_resp.status_code = 401
        unauth_resp.json.return_value = {}

        # Also need a jwks re-fetch after 401
        jwks_resp = MagicMock()
        jwks_resp.status_code = 200
        jwks_resp.raise_for_status = MagicMock()
        jwks_resp.headers = {}
        jwks_resp.json.return_value = {"keys": [rsa_jwk]}

        c._http.get.side_effect = [disc_resp, unauth_resp, jwks_resp]

        with pytest.raises(HearthError):
            c.userinfo("stale-at")


class TestJwksDirect:
    def test_jwks_returns_document(self, rsa_jwk):
        c = _client(rsa_jwk)
        # force_refresh the internal cache state
        c._get_discovery()
        result = c.jwks()
        assert len(result.keys) >= 1

    def test_jwks_raises_on_error_status(self, rsa_jwk):
        c = HearthClient(issuer_url=ISSUER)
        disc_resp = MagicMock()
        disc_resp.status_code = 200
        disc_resp.raise_for_status = MagicMock()
        disc_resp.headers = {}
        disc_resp.json.return_value = {
            "issuer": ISSUER,
            "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        }
        jwks_resp = MagicMock()
        jwks_resp.status_code = 500
        jwks_resp.json.return_value = {}
        http = MagicMock()
        http.get.side_effect = [disc_resp, jwks_resp]
        c._http = http

        with pytest.raises(JwksFetchError):
            c.jwks()


class TestDiscoveryMethod:
    def test_discovery_returns_doc(self, rsa_jwk):
        c = _client(rsa_jwk)
        doc = c.discovery()
        assert "jwks_uri" in doc


class TestBootstrap:
    def test_bootstrap_returns_response(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "admin_token": "at",
            "realm_id": "r",
            "user_id": "u",
            "access_token": "tok",
            "refresh_token": "rtok",
        }
        import httpx
        from unittest.mock import patch

        with patch("httpx.post", return_value=resp):
            result = HearthClient.bootstrap("https://example.com")
        assert result.admin_token == "at"

    def test_bootstrap_raises_on_error(self):
        resp = MagicMock()
        resp.status_code = 500
        resp.json.return_value = {}
        import httpx
        from unittest.mock import patch

        with patch("httpx.post", return_value=resp):
            with pytest.raises(HearthError):
                HearthClient.bootstrap("https://example.com")
