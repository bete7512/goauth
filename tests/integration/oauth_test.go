//go:build integration

package integration_test

import (
	"net/http"
	"net/url"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- GET /oauth/providers ---

func TestOAuth_ListProviders(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	w := h.JSONGet(handler, "/auth/oauth/providers")
	assert.Equal(t, http.StatusOK, w.Code, "list providers: %s", w.Body.String())
}

// --- GET /oauth/linked (auth required) ---

func TestOAuth_LinkedProviders(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)
	token, _ := h.SignupAndLogin(t, handler, "oauth@example.com", "Test1234", "OAuth User")

	w := h.JSONGet(handler, "/auth/oauth/linked", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "linked providers: %s", w.Body.String())
}

func TestOAuth_LinkedProviders_Unauthenticated(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	w := h.JSONGet(handler, "/auth/oauth/linked")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- GET /oauth/{provider} (initiate login) ---

func TestOAuth_InitiateLogin_Google(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	w := h.JSONGet(handler, "/auth/oauth/google")
	assert.Equal(t, http.StatusFound, w.Code, "should redirect: %s", w.Body.String())
	location := w.Header().Get("Location")
	assert.Contains(t, location, "accounts.google.com")
	assert.Contains(t, location, "state=")
	assert.Contains(t, location, "code_challenge=")
}

func TestOAuth_InitiateLogin_GitHub(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	w := h.JSONGet(handler, "/auth/oauth/github")
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "github.com")
}

func TestOAuth_InitiateLogin_UnknownProvider(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	w := h.JSONGet(handler, "/auth/oauth/fakeprovider")
	assert.NotEqual(t, http.StatusFound, w.Code)
}

// --- GET /oauth/{provider}/callback ---

func TestOAuth_Callback_InvalidState(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	w := h.JSONGet(handler, "/auth/oauth/google/callback?code=fake&state=invalid")
	assert.NotEqual(t, http.StatusInternalServerError, w.Code, "should not 500: %s", w.Body.String())
}

func TestOAuth_Callback_MissingCode(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	w := h.JSONGet(handler, "/auth/oauth/google/callback?state=somestate")
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

// --- Full OAuth Flow: Initiate → Fake provider → Callback → Tokens ---
// Uses InterceptingTransport to redirect real OAuth API calls to a fake server.

func TestOAuth_FullFlow_Google(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	// Install fake transport — all requests to googleapis.com go to our fake server
	fake := h.NewFakeOAuthServer(t)
	cleanup := h.InstallFakeTransport(fake.Server.URL)
	defer cleanup()

	// 1. Initiate → get redirect with state
	w := h.JSONGet(handler, "/auth/oauth/google")
	require.Equal(t, http.StatusFound, w.Code)

	parsed, _ := url.Parse(w.Header().Get("Location"))
	state := parsed.Query().Get("state")
	require.NotEmpty(t, state)

	// 2. Callback with valid state + fake code
	// Backend validates state (DB), exchanges code (→ fake server), gets userinfo (→ fake server)
	w = h.JSONGet(handler, "/auth/oauth/google/callback?code=fake_auth_code&state="+state)
	require.Equal(t, http.StatusOK, w.Code, "google callback: %s", w.Body.String())

	data := h.ParseJSON(t, w.Body)
	if d, ok := data["data"].(map[string]interface{}); ok {
		assert.NotEmpty(t, d["access_token"])
		assert.Equal(t, true, d["is_new_user"])
		if user, ok := d["user"].(map[string]interface{}); ok {
			assert.Equal(t, "oauthuser@example.com", user["email"])
		}
	}
}

func TestOAuth_FullFlow_GitHub(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	fake := h.NewFakeOAuthServer(t)
	cleanup := h.InstallFakeTransport(fake.Server.URL)
	defer cleanup()

	w := h.JSONGet(handler, "/auth/oauth/github")
	require.Equal(t, http.StatusFound, w.Code)

	parsed, _ := url.Parse(w.Header().Get("Location"))
	state := parsed.Query().Get("state")

	w = h.JSONGet(handler, "/auth/oauth/github/callback?code=fake_code&state="+state)
	require.Equal(t, http.StatusOK, w.Code, "github callback: %s", w.Body.String())
}

func TestOAuth_SecondLogin_ExistingUser(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	fake := h.NewFakeOAuthServer(t)
	cleanup := h.InstallFakeTransport(fake.Server.URL)
	defer cleanup()

	// First login — creates user
	w := h.JSONGet(handler, "/auth/oauth/google")
	parsed, _ := url.Parse(w.Header().Get("Location"))
	w = h.JSONGet(handler, "/auth/oauth/google/callback?code=c1&state="+parsed.Query().Get("state"))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, true, h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["is_new_user"])

	// Second login — same provider user ID → existing user
	w = h.JSONGet(handler, "/auth/oauth/google")
	parsed, _ = url.Parse(w.Header().Get("Location"))
	w = h.JSONGet(handler, "/auth/oauth/google/callback?code=c2&state="+parsed.Query().Get("state"))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, false, h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["is_new_user"])
}

func TestOAuth_StateReplay_Blocked(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)

	fake := h.NewFakeOAuthServer(t)
	cleanup := h.InstallFakeTransport(fake.Server.URL)
	defer cleanup()

	// Get valid state
	w := h.JSONGet(handler, "/auth/oauth/google")
	parsed, _ := url.Parse(w.Header().Get("Location"))
	state := parsed.Query().Get("state")

	// Use once — succeeds
	w = h.JSONGet(handler, "/auth/oauth/google/callback?code=c1&state="+state)
	require.Equal(t, http.StatusOK, w.Code)

	// Replay same state — must fail
	w = h.JSONGet(handler, "/auth/oauth/google/callback?code=c2&state="+state)
	assert.NotEqual(t, http.StatusOK, w.Code, "replayed state should be rejected")
}

// --- DELETE /oauth/{provider} (unlink) ---

func TestOAuth_Unlink_Unauthenticated(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)
	w := h.JSONDelete(handler, "/auth/oauth/google")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOAuth_Unlink_NotLinked(t *testing.T) {
	_, handler := h.SetupStatelessWithOAuth(t)
	token, _ := h.SignupAndLogin(t, handler, "unlink@example.com", "Test1234", "Unlink")

	w := h.JSONDelete(handler, "/auth/oauth/google", h.AuthHeader(token))
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}
