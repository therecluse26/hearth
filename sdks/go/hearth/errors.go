package hearth

import "fmt"

// Spec §5 — Hearth SDK error types.
//
// All errors implement the standard error interface and can be matched
// with errors.As / errors.Is.

// ConfigurationError is returned when the client is misconfigured
// (e.g. missing BaseURL or RealmID).
type ConfigurationError struct {
	Field   string
	Message string
}

func (e *ConfigurationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("configuration error (%s): %s", e.Field, e.Message)
	}
	return "configuration error: " + e.Message
}

// DiscoveryError is returned when the OIDC discovery document cannot be
// fetched or parsed.
type DiscoveryError struct {
	URL   string
	Cause error
}

func (e *DiscoveryError) Error() string {
	return fmt.Sprintf("discovery error fetching %s: %v", e.URL, e.Cause)
}

func (e *DiscoveryError) Unwrap() error { return e.Cause }

// JWKSFetchError is returned when the JWKS document cannot be retrieved
// or parsed.
type JWKSFetchError struct {
	URL   string
	Cause error
}

func (e *JWKSFetchError) Error() string {
	return fmt.Sprintf("JWKS fetch error from %s: %v", e.URL, e.Cause)
}

func (e *JWKSFetchError) Unwrap() error { return e.Cause }

// TokenExpiredError is returned when a token's exp claim is in the past.
type TokenExpiredError struct {
	ExpiredAt int64 // Unix timestamp
}

func (e *TokenExpiredError) Error() string {
	return fmt.Sprintf("token expired at unix=%d", e.ExpiredAt)
}

// TokenNotYetValidError is returned when a token's nbf claim is in the future.
type TokenNotYetValidError struct {
	NotBefore int64 // Unix timestamp
}

func (e *TokenNotYetValidError) Error() string {
	return fmt.Sprintf("token not yet valid until unix=%d", e.NotBefore)
}

// TokenInvalidError is returned when a token fails structural or signature
// validation.
type TokenInvalidError struct {
	Reason string
}

func (e *TokenInvalidError) Error() string {
	return "token invalid: " + e.Reason
}

// TokenIssuerError is returned when the token's iss claim does not match
// the expected issuer.
type TokenIssuerError struct {
	Expected string
	Actual   string
}

func (e *TokenIssuerError) Error() string {
	return fmt.Sprintf("token issuer mismatch: expected %q, got %q", e.Expected, e.Actual)
}

// TokenAudienceError is returned when the token's aud claim does not contain
// the expected audience.
type TokenAudienceError struct {
	Expected string
	Actual   []string
}

func (e *TokenAudienceError) Error() string {
	return fmt.Sprintf("token audience mismatch: expected %q, got %v", e.Expected, e.Actual)
}

// IntrospectionError is returned when a token introspection request fails
// or returns an inactive token.
type IntrospectionError struct {
	Message string
	Cause   error
}

func (e *IntrospectionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("introspection error: %s: %v", e.Message, e.Cause)
	}
	return "introspection error: " + e.Message
}

func (e *IntrospectionError) Unwrap() error { return e.Cause }
