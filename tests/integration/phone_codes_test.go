//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/pkg/types"
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

// resetCode returns the n-th password-reset code sent to phone, as the SMS
// sender would receive it. Codes are stored only as keyed digests.
func resetCode(t *testing.T, events *h.EventRecorder, phone string, n int) string {
	t.Helper()
	data := h.Nth(t, events, n, func(d *types.PasswordResetRequestData) bool { return d.PhoneNumber == phone && d.Code != "" })
	return data.Code
}

// verificationCode returns the n-th phone-verification code sent to phone.
func verificationCode(t *testing.T, events *h.EventRecorder, phone string, n int) string {
	t.Helper()
	data := h.Nth(t, events, n, func(d *types.PhoneVerificationRequestData) bool {
		return d.User != nil && d.User.PhoneNumber == phone && d.Code != ""
	})
	return data.Code
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
	events := h.RecordEvents(a, types.EventSendPasswordResetEmail)
	const phone, email = "+15550001001", "reset-phone@example.com"
	signupWithPhone(t, handler, email, phone)

	w := h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{"phone": phone})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	code := resetCode(t, events, phone, 1)

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
	fresh := resetCode(t, events, phone, 2)
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
	events := h.RecordEvents(a, types.EventSendPasswordResetEmail)
	signupWithPhone(t, handler, "alice@example.com", "+15550002001")
	signupWithPhone(t, handler, "bob@example.com", "+15550002002")
	for _, phone := range []string{"+15550002001", "+15550002002"} {
		w := h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{"phone": phone})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
	aliceCode := resetCode(t, events, "+15550002001", 1)

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
	events := h.RecordEvents(a, types.EventSendPhoneVerification)
	const phone = "+15550003001"
	signupWithPhone(t, handler, "verify-phone@example.com", phone)

	w := h.JSONPost(handler, "/auth/send-verification-phone", map[string]interface{}{"phone": phone})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	code := verificationCode(t, events, phone, 1)

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
	fresh := verificationCode(t, events, phone, 2)
	w = verifyPhone(handler, phone, fresh)
	require.Equal(t, http.StatusOK, w.Code, "fresh code: %s", w.Body.String())

	user, err := a.Config().Storage.Core().Users().FindByPhoneNumber(context.Background(), phone)
	require.NoError(t, err)
	require.True(t, user.PhoneNumberVerified)
}
