"""Tests for spec §5 error taxonomy."""
import pytest

from hearth.errors import (
    ConfigurationError,
    DiscoveryError,
    HearthError,
    IntrospectionError,
    JWKSFetchError,
    JwksFetchError,
    MiddlewareError,
    TokenAudienceError,
    TokenClaimsError,
    TokenExpiredError,
    TokenInvalidError,
    TokenIssuerError,
    TokenNotYetValidError,
    TokenVerificationError,
)


class TestErrorHierarchy:
    def test_all_nine_types_are_heartherror_subclasses(self):
        classes = [
            ConfigurationError,
            DiscoveryError,
            JwksFetchError,
            TokenVerificationError,
            TokenExpiredError,
            TokenClaimsError,
            IntrospectionError,
            MiddlewareError,
        ]
        for cls in classes:
            assert issubclass(cls, HearthError), f"{cls.__name__} must subclass HearthError"

    def test_granular_claims_errors_subclass_token_claims_error(self):
        assert issubclass(TokenIssuerError, TokenClaimsError)
        assert issubclass(TokenAudienceError, TokenClaimsError)
        assert issubclass(TokenNotYetValidError, TokenClaimsError)

    def test_token_invalid_error_is_alias(self):
        assert TokenInvalidError is TokenVerificationError

    def test_jwks_uppercase_alias(self):
        assert JWKSFetchError is JwksFetchError


class TestErrorMessages:
    def test_configuration_error_includes_field(self):
        e = ConfigurationError("missing value", field="issuer_url")
        assert "issuer_url" in str(e)
        assert "missing value" in str(e)
        assert e.field == "issuer_url"

    def test_configuration_error_no_field(self):
        e = ConfigurationError("oops")
        assert "oops" in str(e)

    def test_discovery_error_stores_url(self):
        e = DiscoveryError("unreachable", url="https://example.com/.well-known/openid-configuration")
        assert e.url == "https://example.com/.well-known/openid-configuration"

    def test_jwks_fetch_error_stores_url(self):
        e = JwksFetchError("bad JSON", url="https://example.com/jwks")
        assert e.url == "https://example.com/jwks"

    def test_token_verification_error_stores_reason(self):
        e = TokenVerificationError("bad signature")
        assert e.reason == "bad signature"
        assert "bad signature" in str(e)

    def test_token_expired_error_stores_timestamp(self):
        e = TokenExpiredError(expired_at=1000)
        assert e.expired_at == 1000
        assert "TokenExpiredError" in str(e)

    def test_token_issuer_error(self):
        e = TokenIssuerError(expected="https://a.example.com", actual="https://b.example.com")
        assert e.expected == "https://a.example.com"
        assert e.actual == "https://b.example.com"

    def test_token_audience_error(self):
        e = TokenAudienceError(expected="client-a", actual=["client-b"])
        assert e.expected == "client-a"
        assert e.actual == ["client-b"]

    def test_token_not_yet_valid_error(self):
        e = TokenNotYetValidError(not_before=9999999999)
        assert e.not_before == 9999999999

    def test_messages_never_include_raw_token(self):
        raw = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"
        for cls, kwargs in [
            (TokenVerificationError, {"reason": "bad"}),
            (TokenExpiredError, {"expired_at": 1}),
            (IntrospectionError, {"message": "failed"}),
            (MiddlewareError, {"message": "oops"}),
        ]:
            e = cls(**kwargs)
            assert raw not in str(e), f"{cls.__name__} leaked a token"


class TestCauseChaining:
    def test_cause_chaining_discovery_error(self):
        cause = ValueError("network error")
        try:
            raise DiscoveryError("failed") from cause
        except DiscoveryError as e:
            assert e.__cause__ is cause

    def test_cause_chaining_jwks_fetch_error(self):
        cause = ConnectionError("timeout")
        try:
            raise JwksFetchError("timeout") from cause
        except JwksFetchError as e:
            assert e.__cause__ is cause

    def test_cause_chaining_token_verification_error(self):
        cause = Exception("decode error")
        try:
            raise TokenVerificationError("bad jwt") from cause
        except TokenVerificationError as e:
            assert e.__cause__ is cause
