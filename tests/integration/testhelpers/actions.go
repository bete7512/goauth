//go:build integration

package testhelpers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Signup creates a new user and asserts 201 Created.
func Signup(t *testing.T, handler http.Handler, email, password, name string) map[string]interface{} {
	t.Helper()
	w := JSONPost(handler, "/auth/signup", map[string]interface{}{
		"email": email, "password": password, "name": name,
	})
	require.Equal(t, http.StatusCreated, w.Code, "signup failed: %s", w.Body.String())
	return ParseJSON(t, w.Body)
}

// Login authenticates a user and asserts 200 OK. Returns (accessToken, refreshToken).
func Login(t *testing.T, handler http.Handler, email, password string) (string, string) {
	t.Helper()
	w := JSONPost(handler, "/auth/login", map[string]interface{}{
		"email": email, "password": password,
	})
	require.Equal(t, http.StatusOK, w.Code, "login failed: %s", w.Body.String())

	data := ParseJSON(t, w.Body)["data"].(map[string]interface{})
	accessToken, ok := data["access_token"].(string)
	require.True(t, ok && accessToken != "", "missing access_token in login response")
	refreshToken, ok := data["refresh_token"].(string)
	require.True(t, ok && refreshToken != "", "missing refresh_token in login response")
	return accessToken, refreshToken
}

// SignupAndLogin is a convenience that creates a user and returns tokens.
func SignupAndLogin(t *testing.T, handler http.Handler, email, password, name string) (string, string) {
	t.Helper()
	Signup(t, handler, email, password, name)
	return Login(t, handler, email, password)
}

// Me calls GET /auth/me with the given token and asserts 200. Returns the user data map.
func Me(t *testing.T, handler http.Handler, token string) map[string]interface{} {
	t.Helper()
	w := JSONGet(handler, "/auth/me", AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code, "me failed: %s", w.Body.String())
	return ParseJSON(t, w.Body)["data"].(map[string]interface{})
}
