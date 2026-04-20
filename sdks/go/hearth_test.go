package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/anthropics/hearth/sdks/go/hearth"
)

// testServer holds a running Hearth dev server and its bootstrap credentials.
type testServer struct {
	port      int
	baseURL   string
	cmd       *exec.Cmd
	bootstrap *hearth.BootstrapResponse
	client    *hearth.Client
}

// findFreePort finds an available port on localhost.
func findFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port, nil
}

// hearthBinPath resolves the hearth binary path.
func hearthBinPath() string {
	// Walk up from test file to find project root
	_, filename, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(filename), "..", "..")

	targetDir := os.Getenv("CARGO_TARGET_DIR")
	if targetDir == "" {
		targetDir = filepath.Join(projectRoot, "target")
	}
	return filepath.Join(targetDir, "debug", "hearth")
}

// startServer starts a Hearth dev server and returns a testServer.
func startServer(t *testing.T) *testServer {
	t.Helper()

	// Build the binary
	buildCmd := exec.Command("cargo", "build", "--bin", "hearth")
	_, filename, _, _ := runtime.Caller(0)
	buildCmd.Dir = filepath.Join(filepath.Dir(filename), "..", "..")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("cargo build failed: %v\n%s", err, out)
	}

	port, err := findFreePort()
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	cmd := exec.Command(hearthBinPath(), "serve", "--dev", "--port", fmt.Sprintf("%d", port))
	cmd.Env = append(os.Environ(), "RUST_LOG=warn")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start hearth: %v", err)
	}

	// Wait for health
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		if ctx.Err() != nil {
			cmd.Process.Kill()
			t.Fatal("hearth did not start in time")
		}
		resp, err := http.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Bootstrap
	bootstrap, err := hearth.Bootstrap(context.Background(), baseURL)
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("bootstrap: %v", err)
	}

	client := hearth.NewClient(baseURL, bootstrap.RealmID)

	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	return &testServer{
		port:      port,
		baseURL:   baseURL,
		cmd:       cmd,
		bootstrap: bootstrap,
		client:    client,
	}
}

func TestAuthCodeFlow(t *testing.T) {
	srv := startServer(t)
	ctx := context.Background()

	// 1. Register an OAuth client
	oauthClient, err := srv.client.RegisterClient(ctx, hearth.RegisterClientRequest{
		ClientName:   "go-test-app",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if oauthClient.ClientID == "" {
		t.Fatal("client_id is empty")
	}

	// 2. Create a user
	admin := srv.client.Admin(srv.bootstrap.AccessToken)
	user, err := admin.CreateUser(ctx, hearth.CreateUserRequest{
		Email:       "go-alice@test.local",
		DisplayName: "Go Alice",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// 3. Authorize
	authResp, err := srv.client.Authorize(ctx, hearth.AuthorizeRequest{
		ClientID:    oauthClient.ClientID,
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "openid profile email",
		State:       "go-state-123",
		UserID:      user.ID,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if authResp.Code == "" {
		t.Fatal("auth code is empty")
	}
	if authResp.State != "go-state-123" {
		t.Fatalf("state mismatch: got %q", authResp.State)
	}

	// 4. Exchange code for tokens
	tokens, err := srv.client.ExchangeCode(ctx, hearth.TokenRequest{
		ClientID:    oauthClient.ClientID,
		Code:        authResp.Code,
		RedirectURI: "http://localhost:3000/callback",
	})
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("access_token is empty")
	}
	if tokens.RefreshToken == "" {
		t.Fatal("refresh_token is empty")
	}
	if tokens.IDToken == "" {
		t.Fatal("id_token is empty")
	}

	// 5. Call userinfo
	userinfo, err := srv.client.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if userinfo.Sub == "" {
		t.Fatal("sub is empty")
	}

	// 6. Refresh tokens
	refreshed, err := srv.client.RefreshTokens(ctx, oauthClient.ClientID, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh tokens: %v", err)
	}
	if refreshed.AccessToken == "" {
		t.Fatal("refreshed access_token is empty")
	}
	if refreshed.AccessToken == tokens.AccessToken {
		t.Fatal("refreshed access_token should differ from original")
	}
}

func TestAdminCRUD(t *testing.T) {
	srv := startServer(t)
	ctx := context.Background()
	admin := srv.client.Admin(srv.bootstrap.AccessToken)

	// === User CRUD ===

	// Create
	user, err := admin.CreateUser(ctx, hearth.CreateUserRequest{
		Email:       "go-crud@test.local",
		DisplayName: "Go CRUD User",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if user.Email != "go-crud@test.local" {
		t.Fatalf("email mismatch: %q", user.Email)
	}

	// Read
	fetched, err := admin.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if fetched.ID != user.ID {
		t.Fatalf("id mismatch: %q != %q", fetched.ID, user.ID)
	}

	// Update
	newName := "Updated Go Name"
	updated, err := admin.UpdateUser(ctx, user.ID, hearth.UpdateUserRequest{
		DisplayName: &newName,
	})
	if err != nil {
		t.Fatalf("update user: %v", err)
	}
	if updated.DisplayName != "Updated Go Name" {
		t.Fatalf("display_name mismatch: %q", updated.DisplayName)
	}

	// List
	page, err := admin.ListUsers(ctx, 10)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(page.Items) < 1 {
		t.Fatal("expected at least 1 user")
	}

	// Delete
	if err := admin.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	// Verify deleted
	_, err = admin.GetUser(ctx, user.ID)
	if err == nil {
		t.Fatal("expected error after delete")
	}
	apiErr, ok := err.(*hearth.APIError)
	if !ok || apiErr.StatusCode != 404 {
		t.Fatalf("expected 404, got: %v", err)
	}

	// === Realm CRUD ===

	// Create
	realm, err := admin.CreateRealm(ctx, hearth.CreateRealmRequest{
		Name: "go-test-realm",
	})
	if err != nil {
		t.Fatalf("create realm: %v", err)
	}
	if realm.Name != "go-test-realm" {
		t.Fatalf("name mismatch: %q", realm.Name)
	}

	// Read
	fetchedRealm, err := admin.GetRealm(ctx, realm.ID)
	if err != nil {
		t.Fatalf("get realm: %v", err)
	}
	if fetchedRealm.ID != realm.ID {
		t.Fatalf("realm id mismatch")
	}

	// Update
	newRealmName := "updated-go-realm"
	updatedRealm, err := admin.UpdateRealm(ctx, realm.ID, hearth.UpdateRealmRequest{
		Name: &newRealmName,
	})
	if err != nil {
		t.Fatalf("update realm: %v", err)
	}
	if updatedRealm.Name != "updated-go-realm" {
		t.Fatalf("realm name mismatch: %q", updatedRealm.Name)
	}

	// Delete
	if err := admin.DeleteRealm(ctx, realm.ID); err != nil {
		t.Fatalf("delete realm: %v", err)
	}

	// Verify deleted
	_, err = admin.GetRealm(ctx, realm.ID)
	if err == nil {
		t.Fatal("expected error after realm delete")
	}
}

func TestTransparentRefresh(t *testing.T) {
	srv := startServer(t)
	ctx := context.Background()

	// 1. Register client and create user
	oauthClient, err := srv.client.RegisterClient(ctx, hearth.RegisterClientRequest{
		ClientName:   "go-refresh-app",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}

	admin := srv.client.Admin(srv.bootstrap.AccessToken)
	user, err := admin.CreateUser(ctx, hearth.CreateUserRequest{
		Email:       "go-refresh@test.local",
		DisplayName: "Go Refresh User",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// 2. Get initial tokens via auth code flow
	authResp, err := srv.client.Authorize(ctx, hearth.AuthorizeRequest{
		ClientID:    oauthClient.ClientID,
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "openid profile email",
		State:       "refresh-test",
		UserID:      user.ID,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	tokens, err := srv.client.ExchangeCode(ctx, hearth.TokenRequest{
		ClientID:    oauthClient.ClientID,
		Code:        authResp.Code,
		RedirectURI: "http://localhost:3000/callback",
	})
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}

	// 3. Refresh tokens
	refreshed1, err := srv.client.RefreshTokens(ctx, oauthClient.ClientID, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if refreshed1.AccessToken == tokens.AccessToken {
		t.Fatal("first refresh should produce a different access token")
	}

	// 4. Use the refreshed access token
	userinfo, err := srv.client.UserInfo(ctx, refreshed1.AccessToken)
	if err != nil {
		t.Fatalf("userinfo after refresh: %v", err)
	}
	if userinfo.Sub == "" {
		t.Fatal("sub is empty after refresh")
	}

	// 5. Refresh again with the new refresh token
	refreshed2, err := srv.client.RefreshTokens(ctx, oauthClient.ClientID, refreshed1.RefreshToken)
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if refreshed2.AccessToken == refreshed1.AccessToken {
		t.Fatal("second refresh should produce a different access token")
	}

	// 6. Verify the latest access token works
	userinfo2, err := srv.client.UserInfo(ctx, refreshed2.AccessToken)
	if err != nil {
		t.Fatalf("userinfo after second refresh: %v", err)
	}
	if userinfo2.Sub != userinfo.Sub {
		t.Fatal("sub should be the same across refreshes")
	}
}
