"""Tests for spec §6 — Flask and FastAPI middleware."""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from hearth.verified_token import VerifiedToken
from tests.conftest import make_rsa_jwt, mock_http, valid_payload

ISSUER = "https://auth.example.com"
CLIENT_ID = "my-client"

flask = pytest.importorskip("flask", reason="flask not installed")
fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(rsa_jwk, rsa_private_key=None):
    """Return a HearthClient wired with a mock HTTP backend."""
    from hearth import HearthClient

    client = HearthClient(issuer_url=ISSUER, client_id=CLIENT_ID)
    client._http = mock_http(jwks_doc={"keys": [rsa_jwk]})
    return client


def _make_token(rsa_private_key, payload_overrides=None):
    payload = valid_payload(ISSUER, CLIENT_ID)
    if payload_overrides:
        payload.update(payload_overrides)
    return make_rsa_jwt(rsa_private_key, "rsa-1", payload)


# ---------------------------------------------------------------------------
# Flask middleware
# ---------------------------------------------------------------------------

class TestFlaskMiddleware:
    @pytest.fixture
    def app(self, rsa_jwk, rsa_private_key):
        from flask import Flask, g, jsonify
        from hearth.middleware import hearth_flask

        client = _make_client(rsa_jwk)
        app = Flask(__name__)
        app.testing = True

        @app.route("/open")
        def open_route():
            return jsonify({"ok": True})

        @app.route("/protected")
        @hearth_flask(client)
        def protected():
            token = g.hearth_token
            return jsonify({"sub": token.subject})

        @app.route("/scoped")
        @hearth_flask(client, required_scope="admin")
        def scoped():
            return jsonify({"ok": True})

        @app.route("/roled")
        @hearth_flask(client, required_role="superuser")
        def roled():
            return jsonify({"ok": True})

        app._rsa_key = rsa_private_key
        return app

    def test_valid_token_passes(self, app, rsa_private_key, rsa_jwk):
        token = _make_token(rsa_private_key)
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.get_json()["sub"] == "user-123"

    def test_missing_header_returns_401(self, app):
        with app.test_client() as c:
            resp = c.get("/protected")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == 'Bearer realm="hearth"'

    def test_malformed_header_returns_401(self, app):
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": "Token abc"})
        assert resp.status_code == 401

    def test_expired_token_returns_401(self, app, rsa_private_key):
        token = _make_token(
            rsa_private_key, {"exp": int(time.time()) - 200}
        )
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Bearer {token}"}, )
        assert resp.status_code == 401

    def test_insufficient_scope_returns_403(self, app, rsa_private_key):
        token = _make_token(rsa_private_key, {"scope": "openid"})
        with app.test_client() as c:
            resp = c.get("/scoped", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_sufficient_scope_passes(self, app, rsa_private_key):
        token = _make_token(rsa_private_key, {"scope": "openid admin"})
        with app.test_client() as c:
            resp = c.get("/scoped", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_insufficient_role_returns_403(self, app, rsa_private_key):
        token = _make_token(rsa_private_key, {"roles": ["viewer"]})
        with app.test_client() as c:
            resp = c.get("/roled", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_sufficient_role_passes(self, app, rsa_private_key):
        token = _make_token(rsa_private_key, {"roles": ["superuser"]})
        with app.test_client() as c:
            resp = c.get("/roled", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# FastAPI middleware
# ---------------------------------------------------------------------------

class TestFastapiMiddleware:
    @pytest.fixture
    def app(self, rsa_jwk, rsa_private_key):
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient
        from hearth.middleware import hearth_fastapi

        client = _make_client(rsa_jwk)
        app = FastAPI()
        auth = hearth_fastapi(client)
        auth_scoped = hearth_fastapi(client, required_scope="admin")
        auth_roled = hearth_fastapi(client, required_role="superuser")

        @app.get("/protected")
        async def protected(token: VerifiedToken = Depends(auth)):
            return {"sub": token.subject}

        @app.get("/scoped")
        async def scoped(token: VerifiedToken = Depends(auth_scoped)):
            return {"ok": True}

        @app.get("/roled")
        async def roled(token: VerifiedToken = Depends(auth_roled)):
            return {"ok": True}

        return TestClient(app, raise_server_exceptions=False)

    def test_valid_token_passes(self, app, rsa_private_key, rsa_jwk):
        token = _make_token(rsa_private_key)
        resp = app.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["sub"] == "user-123"

    def test_missing_header_returns_401(self, app):
        resp = app.get("/protected")
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers

    def test_expired_token_returns_401(self, app, rsa_private_key):
        token = _make_token(rsa_private_key, {"exp": int(time.time()) - 200})
        resp = app.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_insufficient_scope_returns_403(self, app, rsa_private_key):
        token = _make_token(rsa_private_key, {"scope": "openid"})
        resp = app.get("/scoped", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_sufficient_scope_passes(self, app, rsa_private_key):
        token = _make_token(rsa_private_key, {"scope": "openid admin"})
        resp = app.get("/scoped", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_insufficient_role_returns_403(self, app, rsa_private_key):
        token = _make_token(rsa_private_key, {"roles": []})
        resp = app.get("/roled", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_sufficient_role_passes(self, app, rsa_private_key):
        token = _make_token(rsa_private_key, {"roles": ["superuser"]})
        resp = app.get("/roled", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
