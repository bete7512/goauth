//go:build integration

package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/security"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurity_BruteForceAccountLockout(t *testing.T) {
	_, handler := h.SetupAuthWithLockout(t)

	h.Signup(t, handler, "locktest@example.com", "ValidPass1", "Lock Test")

	for i := 0; i < 3; i++ {
		w := h.JSONPost(handler, "/auth/login", map[string]interface{}{
			"email": "locktest@example.com", "password": "WrongPass",
		})
		if i < 2 {
			assert.Equal(t, http.StatusUnauthorized, w.Code, "attempt %d", i+1)
		} else {
			assert.Equal(t, http.StatusLocked, w.Code, "attempt %d should lock", i+1)
		}
	}

	// Correct password still fails while locked
	w := h.JSONPost(handler, "/auth/login", map[string]interface{}{
		"email": "locktest@example.com", "password": "ValidPass1",
	})
	assert.Equal(t, http.StatusLocked, w.Code)
}

func TestSecurity_PasswordPolicyEnforcement(t *testing.T) {
	_, handler := h.SetupAuthWithLockout(t) // MinLength: 8, RequireUppercase: true

	w := h.JSONPost(handler, "/auth/signup", map[string]interface{}{
		"email": "weakpass@example.com", "password": "abc", "name": "Weak",
	})
	assert.NotEqual(t, http.StatusCreated, w.Code, "weak password should be rejected")

	w = h.JSONPost(handler, "/auth/signup", map[string]interface{}{
		"email": "strongpass@example.com", "password": "StrongPass1", "name": "Strong",
	})
	assert.Equal(t, http.StatusCreated, w.Code, "strong password: %s", w.Body.String())
}

func TestSecurity_InvalidJWTSignature(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)

	claims := jwt.MapClaims{"user_id": "fake-user", "exp": time.Now().Add(1 * time.Hour).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	forgedToken, err := token.SignedString([]byte("wrong-secret-key-not-matching!!!"))
	require.NoError(t, err)

	w := h.JSONGet(handler, "/auth/me", h.AuthHeader(forgedToken))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecurity_ExpiredJWT(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)

	claims := jwt.MapClaims{"user_id": "some-user", "exp": time.Now().Add(-1 * time.Hour).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	expiredToken, err := token.SignedString([]byte("integration-test-secret-key-32ch"))
	require.NoError(t, err)

	w := h.JSONGet(handler, "/auth/me", h.AuthHeader(expiredToken))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecurity_EmptyBearerToken(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	w := h.JSONGet(handler, "/auth/me", map[string]string{"Authorization": "Bearer "})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecurity_MalformedAuthorizationHeader(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	w := h.JSONGet(handler, "/auth/me", map[string]string{"Authorization": "NotBearer token123"})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSecurity_SQLInjectionInLogin(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	w := h.JSONPost(handler, "/auth/login", map[string]interface{}{
		"email": "' OR '1'='1' --", "password": "anything",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code, "SQL injection should not cause 500")
}

func TestSecurity_SQLInjectionInSignup(t *testing.T) {
	_, handler := h.SetupStatelessAuth(t)
	w := h.JSONPost(handler, "/auth/signup", map[string]interface{}{
		"email": "test@example.com'; DROP TABLE users; --", "password": "Test1234", "name": "Bobby Tables",
	})
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

func TestSecurity_EncryptionRoundTrip(t *testing.T) {
	mgr := security.NewSecurityManager(types.SecurityConfig{EncryptionKey: "test-encryption-key-for-roundtrip"})

	encrypted, err := mgr.Encrypt("sensitive-token")
	require.NoError(t, err)
	assert.NotEqual(t, "sensitive-token", encrypted)

	decrypted, err := mgr.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, "sensitive-token", decrypted)
}

func TestSecurity_EncryptionDifferentNonce(t *testing.T) {
	mgr := security.NewSecurityManager(types.SecurityConfig{EncryptionKey: "test-key-for-nonce"})
	enc1, _ := mgr.Encrypt("same-data")
	enc2, _ := mgr.Encrypt("same-data")
	assert.NotEqual(t, enc1, enc2)
}

func TestSecurity_RefreshTokenHashedInDB(t *testing.T) {
	token := "my-secret-refresh-token"
	hash := security.HashRefreshToken(token)
	assert.NotEqual(t, token, hash)
	assert.Equal(t, hash, security.HashRefreshToken(token))
	assert.Len(t, hash, 64)
}
