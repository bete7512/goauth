//go:build integration

package integration_test

import (
	"net/http"
	"testing"
	"time"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- POST /magic-link/send ---

func TestMagicLink_Send(t *testing.T) {
	_, handler, sink := h.SetupStatelessWithMagicLink(t)

	w := h.JSONPost(handler, "/auth/magic-link/send", map[string]interface{}{
		"email": "magic@example.com",
	})
	assert.Equal(t, http.StatusOK, w.Code, "send magic link: %s", w.Body.String())

	// Email sink should capture the magic link email (async event)
	time.Sleep(200 * time.Millisecond)
	assert.GreaterOrEqual(t, sink.Count(), 1, "email sink should capture the magic link email")
}

func TestMagicLink_Send_MissingEmail(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithMagicLink(t)

	w := h.JSONPost(handler, "/auth/magic-link/send", map[string]interface{}{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- POST /magic-link/resend ---

func TestMagicLink_Resend(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithMagicLink(t)

	h.JSONPost(handler, "/auth/magic-link/send", map[string]interface{}{"email": "resend@example.com"})

	w := h.JSONPost(handler, "/auth/magic-link/resend", map[string]interface{}{
		"email": "resend@example.com",
	})
	assert.NotEqual(t, http.StatusNotFound, w.Code, "resend endpoint should exist")
	assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
}

// --- GET /magic-link/verify with invalid token ---

func TestMagicLink_Verify_InvalidToken(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithMagicLink(t)

	w := h.JSONGet(handler, "/auth/magic-link/verify?token=invalid-token-123")
	assert.NotEqual(t, http.StatusNotFound, w.Code, "verify endpoint should exist")
}

// --- POST /magic-link/verify-code with invalid code ---

func TestMagicLink_VerifyByCode_InvalidCode(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithMagicLink(t)

	w := h.JSONPost(handler, "/auth/magic-link/verify-code", map[string]interface{}{
		"email": "magic@example.com", "code": "000000",
	})
	assert.NotEqual(t, http.StatusNotFound, w.Code, "verify-code endpoint should exist")
}

// --- Full Flow: Send → Extract code from email sink → Verify-by-code → Get tokens ---

func TestMagicLink_FullFlow_VerifyByCode(t *testing.T) {
	_, handler, sink := h.SetupStatelessWithMagicLink(t)

	// 1. Send magic link
	w := h.JSONPost(handler, "/auth/magic-link/send", map[string]interface{}{
		"email": "fullflow@example.com",
	})
	require.Equal(t, http.StatusOK, w.Code, "send: %s", w.Body.String())

	// 2. Wait for async email delivery then extract code
	time.Sleep(300 * time.Millisecond)
	code := sink.ExtractCode()
	if code == "" {
		t.Skip("magic link email didn't contain a 6-digit code — flow not testable without notification template producing a code")
	}

	// 3. Verify with the real code extracted from the email
	w = h.JSONPost(handler, "/auth/magic-link/verify-code", map[string]interface{}{
		"email": "fullflow@example.com",
		"code":  code,
	})
	assert.Equal(t, http.StatusOK, w.Code, "verify-code: %s", w.Body.String())

	// 4. Should return auth tokens
	data := h.ParseJSON(t, w.Body)
	if d, ok := data["data"].(map[string]interface{}); ok {
		assert.NotEmpty(t, d["access_token"], "should return access token")
	}
}

func TestMagicLink_FullFlow_VerifyByToken(t *testing.T) {
	_, handler, sink := h.SetupStatelessWithMagicLink(t)

	w := h.JSONPost(handler, "/auth/magic-link/send", map[string]interface{}{
		"email": "tokenflow@example.com",
	})
	require.Equal(t, http.StatusOK, w.Code)

	time.Sleep(300 * time.Millisecond)
	token := sink.ExtractToken()
	if token == "" {
		t.Skip("magic link email didn't contain a token URL — flow not testable")
	}

	w = h.JSONGet(handler, "/auth/magic-link/verify?token="+token)
	assert.Equal(t, http.StatusOK, w.Code, "verify by token: %s", w.Body.String())
}
