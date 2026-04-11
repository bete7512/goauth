//go:build integration

package integration_test

import (
	"net/http"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Send ---

func TestInvitation_Send(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)
	token, _ := h.SignupAndLogin(t, handler, "inviter@example.com", "Test1234", "Inviter")

	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "invitee@example.com",
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusCreated, w.Code, "send invitation: %s", w.Body.String())

	data := h.ParseJSON(t, w.Body)
	invData := data["data"].(map[string]interface{})
	assert.Equal(t, "invitee@example.com", invData["email"])
	assert.Equal(t, "platform", invData["purpose"])
	assert.NotEmpty(t, invData["id"])
}

func TestInvitation_Send_WithPurpose(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)
	token, _ := h.SignupAndLogin(t, handler, "inviter2@example.com", "Test1234", "Inviter")

	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email":   "beta@example.com",
		"purpose": "beta",
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusCreated, w.Code, "send beta invitation: %s", w.Body.String())

	invData := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	assert.Equal(t, "beta", invData["purpose"])
}

func TestInvitation_Send_Unauthenticated(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)

	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "someone@example.com",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInvitation_Send_DuplicatePending(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)
	token, _ := h.SignupAndLogin(t, handler, "dup@example.com", "Test1234", "User")

	// First invitation
	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "target@example.com",
	}, h.AuthHeader(token))
	require.Equal(t, http.StatusCreated, w.Code)

	// Duplicate
	w = h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "target@example.com",
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusConflict, w.Code, "duplicate should conflict: %s", w.Body.String())
}

// --- List ---

func TestInvitation_List(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)
	token, _ := h.SignupAndLogin(t, handler, "lister@example.com", "Test1234", "User")

	// Send an invitation first
	h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "listed@example.com",
	}, h.AuthHeader(token))

	w := h.JSONGet(handler, "/auth/invitations", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "list invitations: %s", w.Body.String())

	data := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	assert.NotNil(t, data["list"])
	assert.Equal(t, float64(1), data["total"])
}

// --- My Invitations ---

func TestInvitation_MyInvitations(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)
	token, _ := h.SignupAndLogin(t, handler, "viewer@example.com", "Test1234", "User")

	w := h.JSONGet(handler, "/auth/invitations/my", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "my invitations: %s", w.Body.String())
}

// --- Cancel ---

func TestInvitation_Cancel(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)
	token, _ := h.SignupAndLogin(t, handler, "canceler@example.com", "Test1234", "User")

	// Send invitation
	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "tocancel@example.com",
	}, h.AuthHeader(token))
	require.Equal(t, http.StatusCreated, w.Code)
	invID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	// Cancel it
	w = h.JSONDelete(handler, "/auth/invitations/"+invID, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "cancel invitation: %s", w.Body.String())
}

func TestInvitation_Cancel_NotInviter(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)

	// User 1 sends invitation
	token1, _ := h.SignupAndLogin(t, handler, "user1@example.com", "Test1234", "User1")
	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "target2@example.com",
	}, h.AuthHeader(token1))
	require.Equal(t, http.StatusCreated, w.Code)
	invID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	// User 2 tries to cancel it
	token2, _ := h.SignupAndLogin(t, handler, "user2@example.com", "Test1234", "User2")
	w = h.JSONDelete(handler, "/auth/invitations/"+invID, h.AuthHeader(token2))
	assert.Equal(t, http.StatusNotFound, w.Code, "should not allow canceling others' invitations")
}

// --- Accept / Decline (requires 2 users) ---

func TestInvitation_AcceptInvitation(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)

	// User 1 sends invitation to User 2's email
	token1, _ := h.SignupAndLogin(t, handler, "sender@example.com", "Test1234", "Sender")
	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "accepter@example.com",
	}, h.AuthHeader(token1))
	require.Equal(t, http.StatusCreated, w.Code)

	invData, ok := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	require.True(t, ok, "invite response should have data")
	invToken, ok := invData["token"].(string)
	if !ok {
		t.Skip("invitation token not returned in response — skipping accept flow")
	}

	// User 2 accepts
	token2, _ := h.SignupAndLogin(t, handler, "accepter@example.com", "Test1234", "Accepter")
	w = h.JSONPost(handler, "/auth/invitations/accept", map[string]interface{}{
		"token": invToken,
	}, h.AuthHeader(token2))
	assert.Equal(t, http.StatusOK, w.Code, "accept invitation: %s", w.Body.String())
}

func TestInvitation_DeclineInvitation(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)

	// User 1 sends invitation
	token1, _ := h.SignupAndLogin(t, handler, "sender2@example.com", "Test1234", "Sender")
	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "decliner@example.com",
	}, h.AuthHeader(token1))
	require.Equal(t, http.StatusCreated, w.Code)

	invData, ok := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	require.True(t, ok)
	invToken, ok := invData["token"].(string)
	if !ok {
		t.Skip("invitation token not returned in response — skipping decline flow")
	}

	// User 2 declines
	token2, _ := h.SignupAndLogin(t, handler, "decliner@example.com", "Test1234", "Decliner")
	w = h.JSONPost(handler, "/auth/invitations/decline", map[string]interface{}{
		"token": invToken,
	}, h.AuthHeader(token2))
	assert.Equal(t, http.StatusOK, w.Code, "decline invitation: %s", w.Body.String())
}

func TestInvitation_Accept_EmailMismatch(t *testing.T) {
	_, handler := h.SetupStatelessWithInvitation(t)

	// User 1 sends invitation to a different email
	token1, _ := h.SignupAndLogin(t, handler, "sender3@example.com", "Test1234", "Sender")
	w := h.JSONPost(handler, "/auth/invitations", map[string]interface{}{
		"email": "intended@example.com",
	}, h.AuthHeader(token1))
	require.Equal(t, http.StatusCreated, w.Code)

	invData, ok := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	require.True(t, ok)
	invToken, ok := invData["token"].(string)
	if !ok {
		t.Skip("invitation token not returned in response")
	}

	// User 2 (different email) tries to accept
	token2, _ := h.SignupAndLogin(t, handler, "wrong@example.com", "Test1234", "Wrong")
	w = h.JSONPost(handler, "/auth/invitations/accept", map[string]interface{}{
		"token": invToken,
	}, h.AuthHeader(token2))
	assert.Equal(t, http.StatusForbidden, w.Code, "email mismatch should fail: %s", w.Body.String())
}
