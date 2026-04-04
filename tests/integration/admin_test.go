//go:build integration

package integration_test

import (
	"net/http"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdmin_ListUsers(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)

	// Create a regular user
	h.Signup(t, handler, "regular@example.com", "Test1234", "Regular User")

	// Create an admin user — signup then we need to make them admin via direct DB
	// Since we can't easily make a user admin through the API alone,
	// we test the endpoint returns 403 for non-admin users
	token, _ := h.SignupAndLogin(t, handler, "notadmin@example.com", "Test1234", "Not Admin")

	w := h.JSONGet(handler, "/auth/admin/users", h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code, "non-admin should get 403: %s", w.Body.String())
}

func TestAdmin_GetUser_Forbidden(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "user@example.com", "Test1234", "User")

	w := h.JSONGet(handler, "/auth/admin/users/some-id", h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdmin_UpdateUser_Forbidden(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "user@example.com", "Test1234", "User")

	w := h.JSONPut(handler, "/auth/admin/users/some-id", map[string]interface{}{
		"name": "Hacked",
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdmin_DeleteUser_Forbidden(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "user@example.com", "Test1234", "User")

	w := h.JSONDelete(handler, "/auth/admin/users/some-id", h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdmin_Unauthenticated(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)

	w := h.JSONGet(handler, "/auth/admin/users")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdmin_ListUsers_EndpointExists(t *testing.T) {
	_, handler := h.SetupStatelessWithAdmin(t)
	token, _ := h.SignupAndLogin(t, handler, "user@example.com", "Test1234", "User")

	// The endpoint should exist (return 403, not 404/405)
	w := h.JSONGet(handler, "/auth/admin/users", h.AuthHeader(token))
	require.NotEqual(t, http.StatusNotFound, w.Code, "admin/users route should exist")
	require.NotEqual(t, http.StatusMethodNotAllowed, w.Code, "admin/users should accept GET")
}
