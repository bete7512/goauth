//go:build integration

package integration_test

import (
	"net/http"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
)

func TestProfile_Update(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	token, _ := h.SignupAndLogin(t, handler, "profile@example.com", "Test1234", "Original Name")

	w := h.JSONPut(handler, "/auth/profile", map[string]interface{}{
		"name": "Updated Name",
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "profile update: %s", w.Body.String())

	meData := h.Me(t, handler, token)
	assert.Equal(t, "Updated Name", meData["name"])
}

func TestProfile_CheckAvailability(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	h.Signup(t, handler, "taken@example.com", "Test1234", "Taken")

	// Taken email
	w := h.JSONPost(handler, "/auth/is-available", map[string]interface{}{"email": "taken@example.com"})
	assert.Equal(t, http.StatusOK, w.Code, "check taken: %s", w.Body.String())

	// Free email
	w = h.JSONPost(handler, "/auth/is-available", map[string]interface{}{"email": "free@example.com"})
	assert.Equal(t, http.StatusOK, w.Code, "check free: %s", w.Body.String())
}
