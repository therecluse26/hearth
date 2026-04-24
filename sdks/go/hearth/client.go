package hearth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Client is a Go client for the Hearth identity API.
type Client struct {
	baseURL  string
	realmID string
	http     *http.Client
}

// NewClient creates a new Hearth client.
func NewClient(baseURL, realmID string) *Client {
	return &Client{
		baseURL:  baseURL,
		realmID: realmID,
		http:     &http.Client{},
	}
}

// Bootstrap calls POST /admin/bootstrap in dev mode.
// It creates a realm, admin user, session, and admin tuple.
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

// CheckOptions are optional parameters for Check.
type CheckOptions struct {
	// Zookie, if non-nil, is sent as at_least_as_fresh_as for
	// read-after-write consistency.
	Zookie *uint64
}

// Check performs a batch permission check for the bearer-token user.
// The subject is always derived server-side from the access token; callers
// cannot check permissions on behalf of another user.
func (c *Client) Check(ctx context.Context, accessToken string, checks []CheckRequestItem, opts *CheckOptions) (*CheckResponse, error) {
	body := map[string]any{"checks": checks}
	if opts != nil && opts.Zookie != nil {
		body["at_least_as_fresh_as"] = *opts.Zookie
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/authz/check", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Realm-ID", c.realmID)
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)

	var result CheckResponse
	if err := doRequest(c.http, httpReq, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Capabilities fetches a named capability bundle for the bearer-token user.
// The params map resolves "{var}" placeholders in the server-configured
// object templates for the page.
func (c *Client) Capabilities(ctx context.Context, accessToken, page string, params map[string]string) (*CapabilityBundle, error) {
	query := url.Values{}
	query.Set("page", page)
	for k, v := range params {
		query.Set(k, v)
	}
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/me/capabilities?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("X-Realm-ID", c.realmID)
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)

	var result CapabilityBundle
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
		realmID:    c.realmID,
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
