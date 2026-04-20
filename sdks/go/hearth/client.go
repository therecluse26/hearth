package hearth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
