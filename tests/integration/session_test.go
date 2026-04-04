//go:build integration

package integration_test

import (
	"net/http"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSession_FullFlow(t *testing.T) {
	_, handler := h.SetupSessionAuth(t)

	h.Signup(t, handler, "session@example.com", "Test1234", "Session User")
	accessToken, refreshToken := h.Login(t, handler, "session@example.com", "Test1234")

	h.Me(t, handler, accessToken)

	// Refresh
	w := h.JSONPost(handler, "/auth/refresh", map[string]interface{}{"refresh_token": refreshToken})
	require.Equal(t, http.StatusOK, w.Code, "refresh: %s", w.Body.String())
	newToken := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["access_token"].(string)

	h.Me(t, handler, newToken)

	// Logout
	w = h.JSONPost(handler, "/auth/logout", nil, h.AuthHeader(newToken))
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Session Management Endpoints ---

func TestSession_ListSessions(t *testing.T) {
	_, handler := h.SetupSessionAuth(t)
	token, _ := h.SignupAndLogin(t, handler, "sessions@example.com", "Test1234", "Sessions")

	w := h.JSONGet(handler, "/auth/sessions", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "list sessions: %s", w.Body.String())
}

func TestSession_ListSessions_Unauthenticated(t *testing.T) {
	_, handler := h.SetupSessionAuth(t)

	w := h.JSONGet(handler, "/auth/sessions")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSession_DeleteAllSessions(t *testing.T) {
	_, handler := h.SetupSessionAuth(t)
	token, _ := h.SignupAndLogin(t, handler, "delsessions@example.com", "Test1234", "Del")

	w := h.JSONDelete(handler, "/auth/sessions", h.AuthHeader(token))
	// Should succeed (200) or the token may be immediately invalid
	assert.Contains(t, []int{http.StatusOK, http.StatusUnauthorized}, w.Code,
		"delete all sessions: %s", w.Body.String())
}
