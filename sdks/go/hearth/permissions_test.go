package hearth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// forgeJWT builds a syntactically valid three-segment JWT with the
// given claim body. The signature segment is arbitrary — the SDK does
// not verify it for local boolean checks (the caller trusts its own
// token).
func forgeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(hb) + "." + enc.EncodeToString(cb) + ".c2ln"
}

func TestHasPermission(t *testing.T) {
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{
		"permissions": []string{"docs.edit", "docs.view"},
	})

	if !c.HasPermission(token, "docs.edit") {
		t.Error("expected HasPermission(docs.edit) = true")
	}
	if c.HasPermission(token, "docs.delete") {
		t.Error("expected HasPermission(docs.delete) = false")
	}
}

func TestHasPermissionNegativeCases(t *testing.T) {
	c := NewClient("http://localhost", "r1")

	cases := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"not a JWT", "not-a-jwt"},
		{"two segments", "aa.bb"},
		{"bad base64 payload", "aa.!!!.cc"},
		{"bad json payload", "aa." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".cc"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if c.HasPermission(tc.token, "docs.edit") {
				t.Errorf("expected false for %q", tc.name)
			}
		})
	}
}

func TestHasPermissionMissingClaim(t *testing.T) {
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	if c.HasPermission(token, "docs.edit") {
		t.Error("expected false when permissions claim is absent")
	}
}

func TestHasRole(t *testing.T) {
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"roles": []string{"admin", "editor"}})

	if !c.HasRole(token, "admin") {
		t.Error("expected HasRole(admin) = true")
	}
	if c.HasRole(token, "viewer") {
		t.Error("expected HasRole(viewer) = false")
	}
	if c.HasRole("", "admin") {
		t.Error("expected HasRole over empty token = false")
	}
}

func TestInGroup(t *testing.T) {
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"groups": []string{"engineering", "security"}})

	if !c.InGroup(token, "engineering") {
		t.Error("expected InGroup(engineering) = true")
	}
	if c.InGroup(token, "marketing") {
		t.Error("expected InGroup(marketing) = false")
	}
}

func TestInOrg(t *testing.T) {
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"oid": "org_42"})

	if !c.InOrg(token, "org_42") {
		t.Error("expected InOrg(org_42) = true")
	}
	if c.InOrg(token, "org_7") {
		t.Error("expected InOrg(org_7) = false")
	}
	// missing oid
	tokenNoOid := forgeJWT(t, map[string]any{"sub": "user_1"})
	if c.InOrg(tokenNoOid, "org_42") {
		t.Error("expected false when oid claim absent")
	}
	// empty arg
	if c.InOrg(token, "") {
		t.Error("expected false for empty org id arg")
	}
}

func TestPermissionsHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/me/permissions" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok-abc" {
			t.Errorf("Authorization header: got %q", got)
		}
		if got := r.Header.Get("X-Realm-ID"); got != "r1" {
			t.Errorf("X-Realm-ID header: got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"roles": ["admin"],
			"groups": ["engineering"],
			"permissions": ["docs.edit","docs.view"],
			"scope": "openid profile"
		}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	resp, err := c.Permissions(context.Background(), "tok-abc")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	if len(resp.Permissions) != 2 || resp.Permissions[0] != "docs.edit" {
		t.Errorf("permissions: %+v", resp.Permissions)
	}
	if resp.Scope != "openid profile" {
		t.Errorf("scope: %q", resp.Scope)
	}
	if len(resp.Roles) != 1 || resp.Roles[0] != "admin" {
		t.Errorf("roles: %+v", resp.Roles)
	}
}

func TestPermissionsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	_, err := c.Permissions(context.Background(), "tok-abc")
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("status code: %d", apiErr.StatusCode)
	}
}
