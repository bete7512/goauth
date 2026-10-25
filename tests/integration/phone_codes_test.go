//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/models"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/require"
)

func signupWithPhone(t *testing.T, handler http.Handler, email, phone string) {
	t.Helper()
	w := h.JSONPost(handler, "/auth/signup", map[string]interface{}{
		"email": email, "password": "Test1234", "name": "Phone User", "phone_number": phone,
	})
	require.Equal(t, http.StatusCreated, w.Code, "signup: %s", w.Body.String())
}

// latestCode reads the newest live short code for phone straight from storage,
// standing in for the SMS the user would receive.
func latestCode(t *testing.T, a *auth.Auth, phone, tokenType string) string {
	t.Helper()
	tok, err := a.Config().Storage.Core().Tokens().FindByPhoneAndType(context.Background(), phone, tokenType)
	require.NoError(t, err)
	require.NotEmpty(t, tok.Code)
	return tok.Code
}

func resetWithCode(handler http.Handler, phone, code, password string) *httptest.ResponseRecorder {
	return h.JSONPost(handler, "/auth/reset-password", map[string]interface{}{"phone": phone, "code": code, "new_password": password})
}

func verifyPhone(handler http.Handler, phone, code string) *httptest.ResponseRecorder {
	return h.JSONPost(handler, "/auth/verify-phone", map[string]interface{}{"phone": phone, "code": code})
}

// TestPhoneReset_WrongCodesExhaustTheBudget: five wrong guesses kill the code,
// the right value is then rejected, and a fresh code can be requested at once.
func TestPhoneReset_WrongCodesExhaustTheBudget(t *testing.T) {
	a, handler := h.SetupStatelessAuth(t)
	const phone, email = "+15550001001", "reset-phone@example.com"
	signupWithPhone(t, handler, email, phone)

	w := h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{"phone": phone})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	code := latestCode(t, a, phone, models.TokenTypePasswordReset)

	for i := 1; i <= 4; i++ {
		w = resetWithCode(handler, phone, "000000", "NewPass1234")
		require.Equal(t, http.StatusBadRequest, w.Code, "wrong attempt %d: %s", i, w.Body.String())
	}
	w = resetWithCode(handler, phone, "000000", "NewPass1234")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "fifth wrong attempt: %s", w.Body.String())

	w = resetWithCode(handler, phone, code, "NewPass1234")
	require.NotEqual(t, http.StatusOK, w.Code, "exhausted code must not reset the password")
	w = h.JSONPost(handler, "/auth/login", map[string]interface{}{"email": email, "password": "Test1234"})
	require.Equal(t, http.StatusOK, w.Code, "old password must still work after a failed takeover")

	// A fresh code is issued immediately and works once.
	w = h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{"phone": phone})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	fresh := latestCode(t, a, phone, models.TokenTypePasswordReset)
	w = resetWithCode(handler, phone, fresh, "NewPass1234")
	require.Equal(t, http.StatusOK, w.Code, "fresh code: %s", w.Body.String())
	w = h.JSONPost(handler, "/auth/login", map[string]interface{}{"email": email, "password": "NewPass1234"})
	require.Equal(t, http.StatusOK, w.Code, "login with the new password: %s", w.Body.String())
	w = h.JSONPost(handler, "/auth/login", map[string]interface{}{"email": email, "password": "Test1234"})
	require.Equal(t, http.StatusUnauthorized, w.Code, "old password must be gone")
}

// TestPhoneReset_CodeIsBoundToItsAccount: a valid code for one phone cannot
// reset the password of another account.
func TestPhoneReset_CodeIsBoundToItsAccount(t *testing.T) {
	a, handler := h.SetupStatelessAuth(t)
	signupWithPhone(t, handler, "alice@example.com", "+15550002001")
	signupWithPhone(t, handler, "bob@example.com", "+15550002002")
	for _, phone := range []string{"+15550002001", "+15550002002"} {
		w := h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{"phone": phone})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
	aliceCode := latestCode(t, a, "+15550002001", models.TokenTypePasswordReset)

	w := resetWithCode(handler, "+15550002002", aliceCode, "Hijack1234")
	require.Equal(t, http.StatusBadRequest, w.Code, "another account's code must be a plain wrong guess: %s", w.Body.String())
	w = h.JSONPost(handler, "/auth/login", map[string]interface{}{"email": "bob@example.com", "password": "Test1234"})
	require.Equal(t, http.StatusOK, w.Code, "bob's password must be untouched")

	w = resetWithCode(handler, "+15550002001", aliceCode, "AliceNew1234")
	require.Equal(t, http.StatusOK, w.Code, "alice's own code: %s", w.Body.String())
}

// TestPhoneVerification_WrongCodesExhaustTheBudget mirrors the reset test for
// phone verification codes.
func TestPhoneVerification_WrongCodesExhaustTheBudget(t *testing.T) {
	a, handler := h.SetupStatelessAuth(t)
	const phone = "+15550003001"
	signupWithPhone(t, handler, "verify-phone@example.com", phone)

	w := h.JSONPost(handler, "/auth/send-verification-phone", map[string]interface{}{"phone": phone})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	code := latestCode(t, a, phone, models.TokenTypePhoneVerification)

	for i := 1; i <= 4; i++ {
		w = verifyPhone(handler, phone, "000000")
		require.Equal(t, http.StatusBadRequest, w.Code, "wrong attempt %d: %s", i, w.Body.String())
	}
	w = verifyPhone(handler, phone, "000000")
	require.Equal(t, http.StatusTooManyRequests, w.Code, "fifth wrong attempt: %s", w.Body.String())
	w = verifyPhone(handler, phone, code)
	require.NotEqual(t, http.StatusOK, w.Code, "exhausted code must not verify the phone")

	w = h.JSONPost(handler, "/auth/send-verification-phone", map[string]interface{}{"phone": phone})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	fresh := latestCode(t, a, phone, models.TokenTypePhoneVerification)
	w = verifyPhone(handler, phone, fresh)
	require.Equal(t, http.StatusOK, w.Code, "fresh code: %s", w.Body.String())

	user, err := a.Config().Storage.Core().Users().FindByPhoneNumber(context.Background(), phone)
	require.NoError(t, err)
	require.True(t, user.PhoneNumberVerified)
}
