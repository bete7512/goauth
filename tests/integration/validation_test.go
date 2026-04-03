//go:build integration

package integration_test

import (
	"net/http"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
)

func TestValidation_SignupFields(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)

	tests := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
	}{
		{"missing email", map[string]interface{}{"password": "Test1234", "name": "Test"}, http.StatusBadRequest},
		{"missing password", map[string]interface{}{"email": "test@example.com", "name": "Test"}, http.StatusBadRequest},
		{"valid signup", map[string]interface{}{"email": "valid@example.com", "password": "Test1234", "name": "Valid"}, http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := h.JSONPost(handler, "/auth/signup", tt.body)
			assert.Equal(t, tt.wantStatus, w.Code, "%s: %s", tt.name, w.Body.String())
		})
	}
}

func TestValidation_MultipleUsersIndependent(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)

	token1, _ := h.SignupAndLogin(t, handler, "user1@example.com", "Test1234", "User 1")
	token2, _ := h.SignupAndLogin(t, handler, "user2@example.com", "Test5678", "User 2")

	me1 := h.Me(t, handler, token1)
	assert.Equal(t, "user1@example.com", me1["email"])

	me2 := h.Me(t, handler, token2)
	assert.Equal(t, "user2@example.com", me2["email"])
}
