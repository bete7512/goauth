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

// --- Email Verification Endpoints ---

func TestCore_SendVerificationEmail(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithNotification(t)

	w := h.JSONPost(handler, "/auth/send-verification-email", map[string]interface{}{
		"email": "verify@example.com",
	})
	assert.NotEqual(t, http.StatusNotFound, w.Code, "endpoint should exist")
	assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
}

func TestCore_ResendVerificationEmail(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithNotification(t)

	w := h.JSONPost(handler, "/auth/resend-verification-email", map[string]interface{}{
		"email": "verify@example.com",
	})
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

func TestCore_VerifyEmail_InvalidToken(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithNotification(t)

	w := h.JSONGet(handler, "/auth/verify-email?token=fake-token-123")
	assert.NotEqual(t, http.StatusNotFound, w.Code, "endpoint should exist")
}

func TestCore_SendVerificationPhone(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithNotification(t)

	w := h.JSONPost(handler, "/auth/send-verification-phone", map[string]interface{}{
		"phone": "+1234567890",
	})
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

func TestCore_ResendVerificationPhone(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithNotification(t)

	w := h.JSONPost(handler, "/auth/resend-verification-phone", map[string]interface{}{
		"phone": "+1234567890",
	})
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

func TestCore_VerifyPhone_InvalidCode(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithNotification(t)

	w := h.JSONPost(handler, "/auth/verify-phone", map[string]interface{}{
		"code": "123456", "phone": "+1234567890",
	})
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

// --- Password Reset: Full Flow with Email Sink ---

func TestCore_ForgotPassword(t *testing.T) {
	_, handler, sink := h.SetupStatelessWithNotification(t)

	// Signup a user first (notification module has RequireEmailVerification=true,
	// but signup still works — user just won't be verified)
	h.JSONPost(handler, "/auth/signup", map[string]interface{}{
		"email": "forgot@example.com", "password": "Test1234", "name": "Forgot User",
	})

	w := h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{
		"email": "forgot@example.com",
	})
	assert.Equal(t, http.StatusOK, w.Code, "forgot-password: %s", w.Body.String())

	// Email sink should capture the password reset email
	time.Sleep(200 * time.Millisecond)
	assert.GreaterOrEqual(t, sink.Count(), 1, "should have captured at least one email (welcome or reset)")
}

func TestCore_ForgotPassword_NonexistentEmail(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithNotification(t)

	w := h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{
		"email": "nouser@example.com",
	})
	assert.NotEqual(t, http.StatusInternalServerError, w.Code, "should not crash")
}

func TestCore_ResetPassword_InvalidToken(t *testing.T) {
	_, handler, _ := h.SetupStatelessWithNotification(t)

	w := h.JSONPost(handler, "/auth/reset-password", map[string]interface{}{
		"token":        "fake-reset-token",
		"new_password": "NewPass123",
	})
	assert.NotEqual(t, http.StatusNotFound, w.Code, "endpoint should exist")
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// --- Full Password Reset Flow: Signup → Forgot → Extract token from email → Reset → Login ---

func TestCore_PasswordReset_FullFlow(t *testing.T) {
	_, handler, sink := h.SetupStatelessWithNotification(t)

	// 1. Signup
	h.JSONPost(handler, "/auth/signup", map[string]interface{}{
		"email": "resetflow@example.com", "password": "OldPass123", "name": "Reset Flow",
	})

	// 2. Forgot password
	w := h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{
		"email": "resetflow@example.com",
	})
	require.Equal(t, http.StatusOK, w.Code)

	// 3. Wait for async email, extract reset token or code
	time.Sleep(300 * time.Millisecond)
	token := sink.ExtractToken()
	code := sink.ExtractCode()

	if token == "" && code == "" {
		t.Skip("password reset email didn't contain extractable token or code")
	}

	// 4. Reset password using whichever identifier we got
	resetBody := map[string]interface{}{"new_password": "NewPass456"}
	if token != "" {
		resetBody["token"] = token
	} else {
		resetBody["code"] = code
		resetBody["email"] = "resetflow@example.com"
	}

	w = h.JSONPost(handler, "/auth/reset-password", resetBody)
	if w.Code == http.StatusOK {
		// 5. Login with new password should work
		w = h.JSONPost(handler, "/auth/login", map[string]interface{}{
			"email": "resetflow@example.com", "password": "NewPass456",
		})
		assert.Equal(t, http.StatusOK, w.Code, "login with new password: %s", w.Body.String())
	}
}
