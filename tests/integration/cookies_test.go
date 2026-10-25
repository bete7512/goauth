//go:build integration

package integration_test

import (
	"net/http"
	"strings"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/require"
)

func credentialCookies(t *testing.T, handler http.Handler, email string) []*http.Cookie {
	t.Helper()
	h.Signup(t, handler, email, "Test1234", "Cookie User")
	w := h.JSONPost(handler, "/auth/login", map[string]interface{}{"email": email, "password": "Test1234"})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var cookies []*http.Cookie
	for _, c := range w.Result().Cookies() {
		if strings.HasPrefix(c.Name, "goauth_") {
			cookies = append(cookies, c)
		}
	}
	require.NotEmpty(t, cookies, "login must issue credential cookies")
	return cookies
}

// TestCookies_SecureByDefault: a zero-value cookie configuration issues
// Secure, HttpOnly cookies.
func TestCookies_SecureByDefault(t *testing.T) {
	_, handler := h.SetupSessionAuth(t)
	for _, c := range credentialCookies(t, handler, "secure-cookies@example.com") {
		require.True(t, c.Secure, "cookie %s must be Secure", c.Name)
		require.True(t, c.HttpOnly, "cookie %s must be HttpOnly", c.Name)
	}
}

// TestCookies_InsecureOnlyWhenAllowed: the Secure attribute is dropped only
// when the host explicitly opts out.
func TestCookies_InsecureOnlyWhenAllowed(t *testing.T) {
	_, handler := h.SetupSessionAuthInsecureCookies(t)
	for _, c := range credentialCookies(t, handler, "insecure-cookies@example.com") {
		require.False(t, c.Secure, "cookie %s must not be Secure when AllowInsecureCookies is set", c.Name)
		require.True(t, c.HttpOnly, "cookie %s must stay HttpOnly", c.Name)
	}
}
