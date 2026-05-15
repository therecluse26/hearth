"""Tests for spec §4 VerifiedToken — typed accessors and timing-safe helpers."""
from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from hearth.verified_token import VerifiedToken


@pytest.fixture
def full_payload():
    now = int(time.time())
    return {
        "sub": "user-abc",
        "iss": "https://auth.example.com",
        "aud": ["client-1", "client-2"],
        "iat": now - 60,
        "exp": now + 3600,
        "nbf": now - 300,
        "scope": "openid profile email",
        "roles": ["admin", "viewer"],
        "permissions": ["read:data", "write:data"],
        "jti": "jwt-id-xyz",
        "custom_claim": "hello",
    }


@pytest.fixture
def token(full_payload):
    return VerifiedToken(full_payload)


class TestStandardAccessors:
    def test_subject(self, token):
        assert token.subject == "user-abc"

    def test_issuer(self, token):
        assert token.issuer == "https://auth.example.com"

    def test_audience_list(self, token):
        assert token.audience == ["client-1", "client-2"]

    def test_audience_string_is_normalised_to_list(self):
        t = VerifiedToken({"aud": "single-client"})
        assert t.audience == ["single-client"]

    def test_audience_missing_returns_empty(self):
        assert VerifiedToken({}).audience == []

    def test_issued_at_is_datetime_utc(self, token):
        assert isinstance(token.issued_at, datetime)
        assert token.issued_at.tzinfo == timezone.utc

    def test_expires_at_is_datetime_utc(self, token):
        assert isinstance(token.expires_at, datetime)
        assert token.expires_at.tzinfo == timezone.utc

    def test_not_before_is_datetime_utc(self, token):
        assert isinstance(token.not_before, datetime)
        assert token.not_before.tzinfo == timezone.utc

    def test_missing_timestamps_return_none(self):
        t = VerifiedToken({})
        assert t.issued_at is None
        assert t.expires_at is None
        assert t.not_before is None

    def test_scope_string(self, token):
        assert token.scope == "openid profile email"

    def test_scopes_list(self, token):
        assert token.scopes == ["openid", "profile", "email"]

    def test_empty_scope(self):
        assert VerifiedToken({}).scope == ""
        assert VerifiedToken({}).scopes == []

    def test_raw_returns_copy(self, full_payload, token):
        raw = token.raw
        assert raw == full_payload
        raw["injected"] = True
        assert "injected" not in token.raw  # copy, not reference

    def test_get_custom_claim(self, token):
        assert token.get("custom_claim") == "hello"

    def test_get_missing_returns_none(self, token):
        assert token.get("nonexistent") is None

    def test_repr(self, token):
        assert "user-abc" in repr(token)


class TestHasScope:
    def test_present_scope(self, token):
        assert token.has_scope("openid") is True
        assert token.has_scope("profile") is True

    def test_absent_scope(self, token):
        assert token.has_scope("admin") is False

    def test_partial_match_does_not_count(self, token):
        assert token.has_scope("open") is False

    def test_empty_scope_claim(self):
        t = VerifiedToken({})
        assert t.has_scope("openid") is False

    def test_timing_safe_no_exception_on_empty(self):
        t = VerifiedToken({"scope": ""})
        assert t.has_scope("x") is False


class TestHasRole:
    def test_present_role(self, token):
        assert token.has_role("admin") is True
        assert token.has_role("viewer") is True

    def test_absent_role(self, token):
        assert token.has_role("superuser") is False

    def test_missing_roles_claim_returns_false(self):
        assert VerifiedToken({}).has_role("admin") is False

    def test_none_roles_claim_returns_false(self):
        assert VerifiedToken({"roles": None}).has_role("admin") is False


class TestHasPermission:
    def test_present_permission(self, token):
        assert token.has_permission("read:data") is True
        assert token.has_permission("write:data") is True

    def test_absent_permission(self, token):
        assert token.has_permission("delete:data") is False

    def test_missing_permissions_claim_returns_false(self):
        assert VerifiedToken({}).has_permission("read:data") is False

    def test_none_permissions_claim_returns_false(self):
        assert VerifiedToken({"permissions": None}).has_permission("read:data") is False
