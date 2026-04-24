// Package hearth provides a Go client for the Hearth identity API.
package hearth

// BootstrapResponse is returned by the dev bootstrap endpoint.
type BootstrapResponse struct {
	RealmID     string `json:"realm_id"`
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// AuthorizeRequest contains parameters for the authorization code flow.
type AuthorizeRequest struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
	ResponseType string `json:"response_type"`
	UserID       string `json:"user_id"`
}

// AuthorizeResponse is returned by the authorize endpoint.
type AuthorizeResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// TokenRequest contains parameters for the token exchange.
type TokenRequest struct {
	ClientID     string `json:"client_id"`
	GrantType    string `json:"grant_type,omitempty"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenResponse is returned by the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token"`
}

// UserInfoResponse is returned by the userinfo endpoint.
type UserInfoResponse struct {
	Sub           string `json:"sub"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

// CreateUserRequest contains parameters for creating a user.
type CreateUserRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// User represents a user record from the API.
type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

// UpdateUserRequest contains parameters for updating a user.
type UpdateUserRequest struct {
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Status      *string `json:"status,omitempty"`
}

// CreateRealmRequest contains parameters for creating a realm.
type CreateRealmRequest struct {
	Name string `json:"name"`
}

// Realm represents a realm record from the API.
type Realm struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Status    string      `json:"status"`
	Config    any `json:"config"`
	CreatedAt int64       `json:"created_at,omitempty"`
	UpdatedAt int64       `json:"updated_at,omitempty"`
}

// UpdateRealmRequest contains parameters for updating a realm.
type UpdateRealmRequest struct {
	Name   *string `json:"name,omitempty"`
	Status *string `json:"status,omitempty"`
}

// PageResponse represents a paginated list response.
type PageResponse[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// RegisterClientRequest contains parameters for registering an OAuth client.
type RegisterClientRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// OAuthClient represents an OAuth client record.
type OAuthClient struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
}

// CheckRequestItem is one entry in a batch permission check.
type CheckRequestItem struct {
	// Object is a "type:id" reference, e.g. "doc:readme".
	Object string `json:"object"`
	// Relation is the relation name, e.g. "viewer".
	Relation string `json:"relation"`
}

// CheckResultItem is one result returned from a batch permission check.
type CheckResultItem struct {
	Allowed bool `json:"allowed"`
}

// CheckResponse is the response from POST /v1/authz/check.
type CheckResponse struct {
	Results []CheckResultItem `json:"results"`
	// Token is the zookie echoed back by the server. Used by AuthzCache
	// for read-after-write consistency via at_least_as_fresh_as.
	Token uint64 `json:"token"`
}

// CapabilityBundle is the response from GET /v1/me/capabilities.
type CapabilityBundle struct {
	// Capabilities maps "object#relation" to allowed.
	Capabilities map[string]bool `json:"capabilities"`
	Token        uint64          `json:"token"`
}

// APIError represents an error from the Hearth API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}
