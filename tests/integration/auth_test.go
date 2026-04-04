//go:build integration

package integration_test

import (
	"net/http"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth_BasicSetup(t *testing.T) {
	authInstance, _ := h.SetupStatelessAuth(t)
	routes := authInstance.Routes()
	assert.NotEmpty(t, routes)

	names := make([]string, len(routes))
	for i, r := range routes {
		names[i] = r.Name
	}
	assert.Contains(t, names, "core.signup")
	assert.Contains(t, names, "core.login")
	assert.Contains(t, names, "core.me")
}

func TestAuth_SignupLoginMeLogout(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)

	accessToken, refreshToken := h.SignupAndLogin(t, handler, "alice@example.com", "Test1234", "Alice")

	// Me
	meData := h.Me(t, handler, accessToken)
	assert.Equal(t, "alice@example.com", meData["email"])

	// Refresh
	w := h.JSONPost(handler, "/auth/refresh", map[string]interface{}{
		"refresh_token": refreshToken,
	})
	require.Equal(t, http.StatusOK, w.Code)
	newToken := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["access_token"].(string)

	// Me with refreshed token
	h.Me(t, handler, newToken)

	// Logout
	w = h.JSONPost(handler, "/auth/logout", nil, h.AuthHeader(newToken))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuth_LoginWrongPassword(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	h.Signup(t, handler, "bob@example.com", "Correct123", "Bob")

	w := h.JSONPost(handler, "/auth/login", map[string]interface{}{
		"email": "bob@example.com", "password": "WrongPassword",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_MeWithoutToken(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	w := h.JSONGet(handler, "/auth/me")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_DuplicateSignup(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	h.Signup(t, handler, "carol@example.com", "Test1234", "Carol")

	w := h.JSONPost(handler, "/auth/signup", map[string]interface{}{
		"email": "carol@example.com", "password": "Test1234", "name": "Carol2",
	})
	assert.NotEqual(t, http.StatusCreated, w.Code)
}

func TestAuth_ChangePassword(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	token, _ := h.SignupAndLogin(t, handler, "dave@example.com", "OldPass123", "Dave")

	w := h.JSONPut(handler, "/auth/change-password", map[string]interface{}{
		"old_password": "OldPass123", "new_password": "NewPass456",
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "change password: %s", w.Body.String())

	// New password works
	w = h.JSONPost(handler, "/auth/login", map[string]interface{}{
		"email": "dave@example.com", "password": "NewPass456",
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// Old password fails
	w = h.JSONPost(handler, "/auth/login", map[string]interface{}{
		"email": "dave@example.com", "password": "OldPass123",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_InvalidToken(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	w := h.JSONGet(handler, "/auth/me", h.AuthHeader("invalid.jwt.token"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
} 

func TestAuth_RefreshTokenRotation(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	_, refreshToken := h.SignupAndLogin(t, handler, "eve@example.com", "Test1234", "Eve")

	// Use refresh token
	w := h.JSONPost(handler, "/auth/refresh", map[string]interface{}{"refresh_token": refreshToken})
	assert.Equal(t, http.StatusOK, w.Code)

	// Old refresh token is revoked
	w = h.JSONPost(handler, "/auth/refresh", map[string]interface{}{"refresh_token": refreshToken})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
