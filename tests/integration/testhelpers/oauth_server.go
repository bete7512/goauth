//go:build integration

package testhelpers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FakeOAuthServer simulates an OAuth provider's token and userinfo endpoints.
type FakeOAuthServer struct {
	Server *httptest.Server

	// TokenResponse returned by POST /token (or any path ending in /token)
	TokenResponse map[string]interface{}

	// UserInfoResponse returned by GET /userinfo or /user
	UserInfoResponse map[string]interface{}

	// EmailsResponse returned by GET /user/emails (GitHub-specific)
	EmailsResponse []map[string]interface{}
}

// NewFakeOAuthServer creates a fake OAuth provider server with default responses.
func NewFakeOAuthServer(t *testing.T) *FakeOAuthServer {
	t.Helper()

	fake := &FakeOAuthServer{
		TokenResponse: map[string]interface{}{
			"access_token":  "fake_access_token_123",
			"token_type":    "Bearer",
			"expires_in":    float64(3600),
			"refresh_token": "fake_refresh_token_456",
		},
		UserInfoResponse: map[string]interface{}{
			"sub":            "oauth-user-12345",
			"id":             float64(12345),
			"email":          "oauthuser@example.com",
			"email_verified": true,
			"name":           "OAuth Test User",
			"given_name":     "OAuth",
			"family_name":    "User",
			"picture":        "https://example.com/avatar.jpg",
			"login":          "oauthuser",
			"avatar_url":     "https://example.com/avatar.jpg",
		},
		EmailsResponse: []map[string]interface{}{
			{"email": "oauthuser@example.com", "primary": true, "verified": true},
		},
	}

	fake.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasSuffix(r.URL.Path, "/token") || r.URL.Path == "/token":
			json.NewEncoder(w).Encode(fake.TokenResponse)
		case strings.HasSuffix(r.URL.Path, "/emails"):
			json.NewEncoder(w).Encode(fake.EmailsResponse)
		default:
			// All other requests get userinfo (covers /userinfo, /user, /v1/userinfo, etc.)
			json.NewEncoder(w).Encode(fake.UserInfoResponse)
		}
	}))

	t.Cleanup(func() { fake.Server.Close() })
	return fake
}

// TokenURL returns the fake token endpoint URL.
func (f *FakeOAuthServer) TokenURL() string {
	return f.Server.URL + "/token"
}

// UserInfoURL returns the fake userinfo endpoint URL.
func (f *FakeOAuthServer) UserInfoURL() string {
	return f.Server.URL + "/userinfo"
}

// InterceptingTransport redirects HTTP requests for known OAuth provider
// domains to the fake server. This lets tests run without real provider calls.
type InterceptingTransport struct {
	FakeServerURL string
	Wrapped       http.RoundTripper
}

func (t *InterceptingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host

	// Redirect real OAuth provider API calls to the fake server
	if strings.Contains(host, "googleapis.com") ||
		strings.Contains(host, "github.com") ||
		strings.Contains(host, "api.github.com") ||
		strings.Contains(host, "login.microsoftonline.com") ||
		strings.Contains(host, "discord.com") ||
		strings.Contains(host, "openidconnect.googleapis.com") {

		fakeURL := t.FakeServerURL + req.URL.Path
		newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, fakeURL, req.Body)
		newReq.Header = req.Header
		return t.Wrapped.RoundTrip(newReq)
	}

	return t.Wrapped.RoundTrip(req)
}

// InstallFakeTransport replaces http.DefaultTransport so all OAuth provider
// API calls are redirected to the fake server. Returns a cleanup function
// that restores the original transport.
//
// Usage:
//
//	fake := h.NewFakeOAuthServer(t)
//	cleanup := h.InstallFakeTransport(fake.Server.URL)
//	defer cleanup()
func InstallFakeTransport(fakeServerURL string) func() {
	original := http.DefaultTransport
	http.DefaultTransport = &InterceptingTransport{
		FakeServerURL: fakeServerURL,
		Wrapped:       original,
	}
	return func() {
		http.DefaultTransport = original
	}
}
