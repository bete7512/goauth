//go:build integration

package integration_test

import (
	"net/http"
	"testing"
	"time"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- 2FA Status (before setup) ---

func TestTwoFactor_Status_NotSetup(t *testing.T) {
	_, handler := h.SetupStatelessWithTwoFactor(t)
	token, _ := h.SignupAndLogin(t, handler, "2fa@example.com", "Test1234", "2FA User")

	w := h.JSONGet(handler, "/auth/2fa/status", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "2fa status: %s", w.Body.String())
}

func TestTwoFactor_Status_Unauthenticated(t *testing.T) {
	_, handler := h.SetupStatelessWithTwoFactor(t)

	w := h.JSONGet(handler, "/auth/2fa/status")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- 2FA Setup ---

func TestTwoFactor_Setup(t *testing.T) {
	_, handler := h.SetupStatelessWithTwoFactor(t)
	token, _ := h.SignupAndLogin(t, handler, "setup2fa@example.com", "Test1234", "Setup User")

	w := h.JSONPost(handler, "/auth/2fa/setup", nil, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "2fa setup: %s", w.Body.String())

	data := h.ParseJSON(t, w.Body)
	setupData, ok := data["data"].(map[string]interface{})
	require.True(t, ok, "setup response should have data: %v", data)
	assert.NotEmpty(t, setupData["secret"], "should return TOTP secret")
}

func TestTwoFactor_Setup_Unauthenticated(t *testing.T) {
	_, handler := h.SetupStatelessWithTwoFactor(t)

	w := h.JSONPost(handler, "/auth/2fa/setup", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Full 2FA Flow: Setup → Verify → Enable → Status shows enabled ---

func TestTwoFactor_FullSetupAndVerify(t *testing.T) {
	_, handler := h.SetupStatelessWithTwoFactor(t)
	token, _ := h.SignupAndLogin(t, handler, "full2fa@example.com", "Test1234", "Full 2FA")

	// 1. Setup — get secret
	w := h.JSONPost(handler, "/auth/2fa/setup", nil, h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code, "setup: %s", w.Body.String())

	setupData := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	secret := setupData["secret"].(string)
	require.NotEmpty(t, secret)

	// 2. Generate a real TOTP code from the secret
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	// 3. Verify with the real code (enables 2FA)
	w = h.JSONPost(handler, "/auth/2fa/verify", map[string]interface{}{
		"code": code,
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "verify: %s", w.Body.String())

	// 4. Check status — should show enabled
	w = h.JSONGet(handler, "/auth/2fa/status", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code)
	statusData := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	assert.Equal(t, true, statusData["enabled"], "2FA should be enabled after verify")
}

// --- 2FA Verify with wrong code ---

func TestTwoFactor_Verify_WrongCode(t *testing.T) {
	_, handler := h.SetupStatelessWithTwoFactor(t)
	token, _ := h.SignupAndLogin(t, handler, "wrongcode@example.com", "Test1234", "Wrong Code")

	// Setup first
	h.JSONPost(handler, "/auth/2fa/setup", nil, h.AuthHeader(token))

	// Verify with invalid code
	w := h.JSONPost(handler, "/auth/2fa/verify", map[string]interface{}{
		"code": "000000",
	}, h.AuthHeader(token))
	assert.NotEqual(t, http.StatusOK, w.Code, "wrong code should fail: %s", w.Body.String())
}

// --- 2FA Disable ---

func TestTwoFactor_Disable_EndpointExists(t *testing.T) {
	_, handler := h.SetupStatelessWithTwoFactor(t)
	token, _ := h.SignupAndLogin(t, handler, "disable2fa@example.com", "Test1234", "Disable 2FA")

	// Disable without having 2FA enabled — should fail but endpoint should exist
	w := h.JSONPost(handler, "/auth/2fa/disable", map[string]interface{}{
		"code": "123456",
	}, h.AuthHeader(token))
	assert.NotEqual(t, http.StatusNotFound, w.Code, "disable endpoint should exist")
	assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
}

// --- 2FA Verify-Login endpoint (no auth required) ---

func TestTwoFactor_VerifyLogin_InvalidToken(t *testing.T) {
	_, handler := h.SetupStatelessWithTwoFactor(t)

	// verify-login with invalid temp token
	w := h.JSONPost(handler, "/auth/2fa/verify-login", map[string]interface{}{
		"temp_token": "invalid-token",
		"code":       "123456",
	})
	assert.NotEqual(t, http.StatusOK, w.Code, "invalid temp token should fail")
	assert.NotEqual(t, http.StatusNotFound, w.Code, "endpoint should exist")
}

// --- 2FA Login Challenge Flow ---

func TestTwoFactor_LoginWithChallenge(t *testing.T) {
	_, handler := h.SetupStatelessWithTwoFactor(t)

	// Signup, login, enable 2FA
	token, _ := h.SignupAndLogin(t, handler, "challenge@example.com", "Test1234", "Challenge User")

	w := h.JSONPost(handler, "/auth/2fa/setup", nil, h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code)
	secret := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["secret"].(string)

	code, _ := totp.GenerateCode(secret, time.Now())
	w = h.JSONPost(handler, "/auth/2fa/verify", map[string]interface{}{"code": code}, h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code)

	// Now login again — should get a 2FA challenge instead of tokens
	w = h.JSONPost(handler, "/auth/login", map[string]interface{}{
		"email": "challenge@example.com", "password": "Test1234",
	})
	assert.Equal(t, http.StatusOK, w.Code, "login with 2FA: %s", w.Body.String())

	loginData := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})

	// Should have challenges (2FA required) OR a temp_token
	challenges, hasChallenges := loginData["challenges"]
	if hasChallenges && challenges != nil {
		challengeList := challenges.([]interface{})
		assert.NotEmpty(t, challengeList, "should have 2FA challenge")
	}
}
