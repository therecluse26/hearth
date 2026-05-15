package hearth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Claims is the spec §4 Claims API — a typed accessor for a decoded JWT payload.
//
// Construct via ParseClaims. All methods are local; no network call is made.
// Signature verification is the caller's responsibility.
type Claims struct {
	// Standard OIDC claims — field names match spec §4 identifiers so that
	// spec conformance tooling can locate them.
	subject     string
	issuer      string
	audiences   []string
	expiry      int64
	issuedAt    int64
	jwtID       string
	scopes      []string
	roles       []string
	permissions []string
	raw         map[string]json.RawMessage
}

// rawClaims is the internal JSON shape of a Hearth JWT payload.
type rawClaims struct {
	Sub         string          `json:"sub"`
	Iss         string          `json:"iss"`
	Aud         audClaim        `json:"aud"`
	Exp         int64           `json:"exp"`
	Iat         int64           `json:"iat"`
	Jti         string          `json:"jti"`
	Scope       string          `json:"scope"`
	Roles       []string        `json:"roles"`
	Permissions []string        `json:"permissions"`
	Extra       json.RawMessage `json:"-"`
}

// audClaim handles both single-string and array-of-string aud values.
type audClaim []string

func (a *audClaim) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

// ParseClaims decodes the middle segment of a JWT and returns a Claims
// accessor. The signature is NOT verified.
//
// Returns TokenInvalidError when the string is not a valid JWT.
func ParseClaims(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, &TokenInvalidError{Reason: "expected three dot-separated segments"}
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, &TokenInvalidError{Reason: "base64 decode of payload failed: " + err.Error()}
		}
	}

	var rc rawClaims
	if err := json.Unmarshal(payload, &rc); err != nil {
		return nil, &TokenInvalidError{Reason: "JSON unmarshal of payload failed: " + err.Error()}
	}

	var rawMap map[string]json.RawMessage
	_ = json.Unmarshal(payload, &rawMap)

	scopes := splitScope(rc.Scope)

	return &Claims{
		subject:     rc.Sub,
		issuer:      rc.Iss,
		audiences:   []string(rc.Aud),
		expiry:      rc.Exp,
		issuedAt:    rc.Iat,
		jwtID:       rc.Jti,
		scopes:      scopes,
		roles:       rc.Roles,
		permissions: rc.Permissions,
		raw:         rawMap,
	}, nil
}

// Subject returns the sub (subject) claim.
func (c *Claims) Subject() string { return c.subject }

// Issuer returns the iss (issuer) claim.
func (c *Claims) Issuer() string { return c.issuer }

// Audiences returns the aud (audiences) claim, normalised to a slice.
func (c *Claims) Audiences() []string { return c.audiences }

// Expiry returns the exp claim as a Unix timestamp, or 0 if absent.
func (c *Claims) Expiry() int64 { return c.expiry }

// IssuedAt returns the iat claim as a Unix timestamp, or 0 if absent.
func (c *Claims) IssuedAt() int64 { return c.issuedAt }

// JwtID returns the jti claim, or an empty string if absent.
func (c *Claims) JwtID() string { return c.jwtID }

// Scopes returns the individual scopes from the scope claim.
func (c *Claims) Scopes() []string { return c.scopes }

// HasScope reports whether the token contains the given scope.
// Spec §4 predicate — delegates to the unexported hasScope helper.
func (c *Claims) HasScope(scope string) bool { return hasScope(c.scopes, scope) }

// HasRole reports whether the token's roles claim contains the given role.
// Spec §4 predicate — delegates to the unexported hasRole helper.
func (c *Claims) HasRole(role string) bool { return hasRole(c.roles, role) }

// HasPermission reports whether the token's permissions claim contains perm.
// Spec §4 predicate — delegates to the unexported hasPermission helper.
func (c *Claims) HasPermission(perm string) bool { return hasPermission(c.permissions, perm) }

// Get returns a raw JSON message for the given claim key, or nil if absent.
func (c *Claims) Get(key string) json.RawMessage { return c.raw[key] }

// hasScope is an unexported predicate used by Claims.HasScope (spec §4).
func hasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// hasRole is an unexported predicate used by Claims.HasRole (spec §4).
func hasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// hasPermission is an unexported predicate used by Claims.HasPermission (spec §4).
func hasPermission(permissions []string, perm string) bool {
	for _, p := range permissions {
		if p == perm {
			return true
		}
	}
	return false
}

func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	parts := strings.Fields(scope)
	if len(parts) == 0 {
		return nil
	}
	return parts
}
