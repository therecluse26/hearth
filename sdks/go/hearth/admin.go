package hearth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// AdminClient provides access to the Hearth admin API.
type AdminClient struct {
	baseURL     string
	realmID    string
	accessToken string
	http        *http.Client
}

// CreateUser creates a new user via the admin API.
func (a *AdminClient) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	var result User
	if err := a.post(ctx, "/admin/users", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUser retrieves a user by ID via the admin API.
func (a *AdminClient) GetUser(ctx context.Context, userID string) (*User, error) {
	var result User
	if err := a.get(ctx, fmt.Sprintf("/admin/users/%s", userID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateUser updates a user via the admin API.
func (a *AdminClient) UpdateUser(ctx context.Context, userID string, req UpdateUserRequest) (*User, error) {
	var result User
	if err := a.request(ctx, "PUT", fmt.Sprintf("/admin/users/%s", userID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteUser deletes a user via the admin API.
func (a *AdminClient) DeleteUser(ctx context.Context, userID string) error {
	return a.request(ctx, "DELETE", fmt.Sprintf("/admin/users/%s", userID), nil, nil)
}

// ListUsers lists users with optional pagination.
func (a *AdminClient) ListUsers(ctx context.Context, limit int) (*PageResponse[User], error) {
	path := fmt.Sprintf("/admin/users?limit=%d", limit)
	var result PageResponse[User]
	if err := a.get(ctx, path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateRealm creates a new realm via the admin API.
func (a *AdminClient) CreateRealm(ctx context.Context, req CreateRealmRequest) (*Realm, error) {
	var result Realm
	if err := a.post(ctx, "/admin/realms", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetRealm retrieves a realm by ID via the admin API.
func (a *AdminClient) GetRealm(ctx context.Context, realmID string) (*Realm, error) {
	var result Realm
	if err := a.get(ctx, fmt.Sprintf("/admin/realms/%s", realmID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateRealm updates a realm via the admin API.
func (a *AdminClient) UpdateRealm(ctx context.Context, realmID string, req UpdateRealmRequest) (*Realm, error) {
	var result Realm
	if err := a.request(ctx, "PUT", fmt.Sprintf("/admin/realms/%s", realmID), req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteRealm deletes a realm via the admin API.
func (a *AdminClient) DeleteRealm(ctx context.Context, realmID string) error {
	return a.request(ctx, "DELETE", fmt.Sprintf("/admin/realms/%s", realmID), nil, nil)
}

func (a *AdminClient) headers(req *http.Request) {
	req.Header.Set("X-Realm-ID", a.realmID)
	req.Header.Set("Authorization", "Bearer "+a.accessToken)
	req.Header.Set("Content-Type", "application/json")
}

func (a *AdminClient) get(ctx context.Context, path string, result any) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+path, nil)
	if err != nil {
		return err
	}
	a.headers(httpReq)
	return doRequest(a.http, httpReq, result)
}

func (a *AdminClient) post(ctx context.Context, path string, body, result any) error {
	return a.request(ctx, "POST", path, body, result)
}

func (a *AdminClient) request(ctx context.Context, method, path string, body, result any) error {
	var bodyReader *bytes.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	var httpReq *http.Request
	var err error
	if bodyReader != nil {
		httpReq, err = http.NewRequestWithContext(ctx, method, a.baseURL+path, bodyReader)
	} else {
		httpReq, err = http.NewRequestWithContext(ctx, method, a.baseURL+path, nil)
	}
	if err != nil {
		return err
	}
	a.headers(httpReq)
	return doRequest(a.http, httpReq, result)
}
