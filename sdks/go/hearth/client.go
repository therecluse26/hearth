package hearth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Client is a Go client for the Hearth identity API.
type Client struct {
	baseURL string
	realmID string
	http    *http.Client
}

// NewClient creates a new Hearth client.
func NewClient(baseURL, realmID string) *Client {
	return &Client{
		baseURL: baseURL,
		realmID: realmID,
		http:    &http.Client{},
	}
}

// Bootstrap calls POST /admin/bootstrap in dev mode.
// It creates a realm, admin user, session, and admin role assignment.
func Bootstrap(ctx context.Context, baseURL string) (*BootstrapResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/admin/bootstrap", nil)
	if err != nil {
		return nil, err
	}
	var result BootstrapResponse
	if err := doRequest(&http.Client{}, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RegisterClient registers a new OAuth 2.0 client.
func (c *Client) RegisterClient(ctx context.Context, req RegisterClientRequest) (*OAuthClient, error) {
	var result OAuthClient
	if err := c.post(ctx, "/clients", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Authorize initiates an authorization code flow.
func (c *Client) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error) {
	if req.ResponseType == "" {
		req.ResponseType = "code"
	}
	var result AuthorizeResponse
	if err := c.post(ctx, "/authorize", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExchangeCode exchanges an authorization code for tokens.
func (c *Client) ExchangeCode(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	var result TokenResponse
	if err := c.post(ctx, "/token", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RefreshTokens exchanges a refresh token for new tokens.
func (c *Client) RefreshTokens(ctx context.Context, clientID, refreshToken string) (*TokenResponse, error) {
	req := TokenRequest{
		ClientID:     clientID,
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
	}
	var result TokenResponse
	if err := c.post(ctx, "/token", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// rbacClaims mirrors the RBAC-relevant subset of Hearth TokenClaims.
// Only fields required by HasPermission/HasRole/InGroup/InOrg are
// decoded; everything else is ignored.
type rbacClaims struct {
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
	Groups      []string `json:"groups"`
	OID         string   `json:"oid"`
}

// decodeClaims returns the parsed RBAC claim set from a JWT's middle
// segment. The signature is NOT verified — the app trusts its own
// token. Returns nil when the token is absent, malformed, or the
// claim segment fails to decode / parse.
func decodeClaims(token string) *rbacClaims {
	if token == "" {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers produce padded base64url; try the padded variant.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var claims rbacClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return &claims
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// HasPermission returns true iff the JWT's `permissions` claim contains
// the given permission. Decoding is local — no network call. Returns
// false for an empty or malformed token.
func (c *Client) HasPermission(token, permission string) bool {
	claims := decodeClaims(token)
	return claims != nil && contains(claims.Permissions, permission)
}

// HasRole returns true iff the JWT's `roles` claim contains the given
// role. Decoding is local.
func (c *Client) HasRole(token, role string) bool {
	claims := decodeClaims(token)
	return claims != nil && contains(claims.Roles, role)
}

// InGroup returns true iff the JWT's `groups` claim contains the given
// group slug. Decoding is local.
func (c *Client) InGroup(token, groupSlug string) bool {
	claims := decodeClaims(token)
	return claims != nil && contains(claims.Groups, groupSlug)
}

// InOrg returns true iff the JWT's `oid` claim equals the given org
// ID. Decoding is local.
func (c *Client) InOrg(token, orgID string) bool {
	claims := decodeClaims(token)
	return claims != nil && claims.OID == orgID && orgID != ""
}

// Permissions fetches the freshly-resolved permission set via
// GET /v1/me/permissions. Returns the claim set as the server resolves
// it right now — not the possibly-stale set baked into the JWT.
func (c *Client) Permissions(ctx context.Context, token string) (*MePermissionsResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/me/permissions", nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("X-Realm-ID", c.realmID)
	httpReq.Header.Set("Authorization", "Bearer "+token)

	var result MePermissionsResponse
	if err := doRequest(c.http, httpReq, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UserInfo retrieves user claims using an access token.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfoResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/userinfo", nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("X-Realm-ID", c.realmID)
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)

	var result UserInfoResponse
	if err := doRequest(c.http, httpReq, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Admin creates an AdminClient using the given access token.
func (c *Client) Admin(accessToken string) *AdminClient {
	return &AdminClient{
		baseURL:     c.baseURL,
		realmID:     c.realmID,
		accessToken: accessToken,
		http:        c.http,
	}
}

func (c *Client) post(ctx context.Context, path string, body, result any) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Realm-ID", c.realmID)

	return doRequest(c.http, httpReq, result)
}

func doRequest(client *http.Client, req *http.Request, result any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}
	}

	if result != nil {
		return json.Unmarshal(body, result)
	}
	return nil
}
