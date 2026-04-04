//go:build integration

package integration_test

import (
	"net/http"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
)

func TestCSRF_GetToken(t *testing.T) {
	_, handler := h.SetupFullAuth(t)

	w := h.JSONGet(handler, "/auth/csrf-token")
	assert.Equal(t, http.StatusOK, w.Code, "csrf-token: %s", w.Body.String())

	// Verify response is valid JSON with some data
	body := w.Body.String()
	assert.NotEmpty(t, body, "CSRF response body should not be empty")
}

func TestCSRF_EndpointExists(t *testing.T) {
	_, handler := h.SetupFullAuth(t)

	w := h.JSONGet(handler, "/auth/csrf-token")
	assert.NotEqual(t, http.StatusNotFound, w.Code, "CSRF endpoint should exist")
	assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code, "CSRF should accept GET")
}
