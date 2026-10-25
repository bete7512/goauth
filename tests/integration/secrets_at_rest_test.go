//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/require"
)

// TestSecrets_ResetTokenAndCodeStoredAsDigests: the database holds only
// digests of the delivered reset token and code, the delivered values work,
// and a digest copied out of the database is rejected as a token.
func TestSecrets_ResetTokenAndCodeStoredAsDigests(t *testing.T) {
	a, handler := h.SetupStatelessAuthWithFrontend(t, &config.FrontendConfig{URL: "https://app.example.com", ResetPasswordPath: "/reset"})
	events := h.RecordEvents(a, types.EventSendPasswordResetEmail)
	tokens := a.Config().Storage.Core().Tokens()
	ctx := context.Background()
	const email, phone = "at-rest@example.com", "+15550004001"
	signupWithPhone(t, handler, email, phone)

	// Email reset: the link carries the token, the row carries its digest.
	w := h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{"email": email})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	sent := h.Nth(t, events, 1, func(d *types.PasswordResetRequestData) bool { return d.Email == email && d.ResetLink != "" })
	raw := sent.ResetLink[strings.Index(sent.ResetLink, "token=")+len("token="):]
	row, err := tokens.FindByEmailAndType(ctx, email, models.TokenTypePasswordReset)
	require.NoError(t, err)
	require.NotEqual(t, raw, row.Token, "the raw token must not be stored")
	require.True(t, strings.HasPrefix(row.Token, "s1:"), "stored token %q is not a digest", row.Token)

	w = h.JSONPost(handler, "/auth/reset-password", map[string]interface{}{"token": row.Token, "new_password": "Stolen1234"})
	require.NotEqual(t, http.StatusOK, w.Code, "a digest read from the database must not reset the password")
	w = h.JSONPost(handler, "/auth/reset-password", map[string]interface{}{"token": raw, "new_password": "NewPass1234"})
	require.Equal(t, http.StatusOK, w.Code, "the delivered token: %s", w.Body.String())

	// Phone reset: the SMS carries the code, the row carries a keyed digest.
	w = h.JSONPost(handler, "/auth/forgot-password", map[string]interface{}{"phone": phone})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	code := h.Nth(t, events, 1, func(d *types.PasswordResetRequestData) bool { return d.PhoneNumber == phone && d.Code != "" }).Code
	row, err = tokens.FindByPhoneAndType(ctx, phone, models.TokenTypePasswordReset)
	require.NoError(t, err)
	require.NotEqual(t, code, row.Code, "the raw code must not be stored")
	require.True(t, strings.HasPrefix(row.Code, "h1:"), "stored code %q is not a digest", row.Code)
	require.False(t, strings.Contains(row.Token, code))

	w = resetWithCode(handler, phone, row.Code, "Stolen1234")
	require.Equal(t, http.StatusBadRequest, w.Code, "a code digest read from the database must not work: %s", w.Body.String())
	w = resetWithCode(handler, phone, code, "Phone1234")
	require.Equal(t, http.StatusOK, w.Code, "the delivered code: %s", w.Body.String())
}

// TestSecrets_InvitationTokenStoredAsDigest: invitations store only the digest
// of the token in the emailed link.
func TestSecrets_InvitationTokenStoredAsDigest(t *testing.T) {
	a, handler := h.SetupStatelessWithInvitation(t)
	events := h.RecordEvents(a, types.EventInvitationSent)
	adminToken, _ := invitationAdmin(t, a, handler, "digest-admin@example.com", "Test1234", "Admin")
	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{"email": "digest-invitee@example.com"}, h.AuthHeader(adminToken))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	id := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	raw := h.InvitationToken(t, events, id)
	stored, err := a.Config().Storage.Invitation().Invitations().FindByID(context.Background(), id)
	require.NoError(t, err)
	require.NotEqual(t, raw, stored.Token)
	require.True(t, strings.HasPrefix(stored.Token, "s1:"), "stored invitation token %q is not a digest", stored.Token)

	invitee, _ := h.SignupAndLogin(t, handler, "digest-invitee@example.com", "Test1234", "Invitee")
	w = h.JSONPost(handler, "/auth/invitations/accept", map[string]interface{}{"token": stored.Token}, h.AuthHeader(invitee))
	require.NotEqual(t, http.StatusOK, w.Code, "a digest read from the database must not accept the invitation")
	w = h.JSONPost(handler, "/auth/invitations/accept", map[string]interface{}{"token": raw}, h.AuthHeader(invitee))
	require.Equal(t, http.StatusOK, w.Code, "the delivered token: %s", w.Body.String())
}
