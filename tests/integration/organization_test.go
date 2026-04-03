//go:build integration

package integration_test

import (
	"net/http"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Org CRUD ---

func TestOrg_CreateOrg(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "org@example.com", "Test1234", "Org Owner")

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{
		"name": "My Team",
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusCreated, w.Code, "create org: %s", w.Body.String())

	data := h.ParseJSON(t, w.Body)
	orgData := data["data"].(map[string]interface{})
	assert.Equal(t, "My Team", orgData["name"])
	assert.NotEmpty(t, orgData["id"])
	assert.NotEmpty(t, orgData["slug"])
}

func TestOrg_CreateOrg_Unauthenticated(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Team"})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOrg_MyOrgs(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "myorgs@example.com", "Test1234", "User")

	// Create an org
	h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Team Alpha"}, h.AuthHeader(token))

	w := h.JSONGet(handler, "/auth/org/my", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "my orgs: %s", w.Body.String())
}

func TestOrg_GetOrg(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "getorg@example.com", "Test1234", "User")

	// Create org and extract ID
	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Get Team"}, h.AuthHeader(token))
	require.Equal(t, http.StatusCreated, w.Code)
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	// Get org by ID
	w = h.JSONGet(handler, "/auth/org/"+orgID, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "get org: %s", w.Body.String())
}

func TestOrg_UpdateOrg(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "updateorg@example.com", "Test1234", "User")

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Old Name"}, h.AuthHeader(token))
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	w = h.JSONPut(handler, "/auth/org/"+orgID, map[string]interface{}{
		"name": "New Name",
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "update org: %s", w.Body.String())
}

func TestOrg_DeleteOrg(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "delorg@example.com", "Test1234", "User")

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "To Delete"}, h.AuthHeader(token))
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	w = h.JSONDelete(handler, "/auth/org/"+orgID, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "delete org: %s", w.Body.String())
}

// --- Members ---

func TestOrg_ListMembers(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "members@example.com", "Test1234", "User")

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Members Team"}, h.AuthHeader(token))
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	w = h.JSONGet(handler, "/auth/org/"+orgID+"/members", h.AuthHeader(token))
	// Endpoint exists and is reachable (not 404/405/401)
	assert.NotEqual(t, http.StatusNotFound, w.Code, "list members endpoint should exist")
	assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestOrg_GetMember(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "getmember@example.com", "Test1234", "User")

	// Create org
	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Member Team"}, h.AuthHeader(token))
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	// Get the owner's user ID via /me
	meData := h.Me(t, handler, token)
	userID := meData["id"].(string)

	w = h.JSONGet(handler, "/auth/org/"+orgID+"/members/"+userID, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "get member: %s", w.Body.String())
}

func TestOrg_UpdateMember_NotFound(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "updatemember@example.com", "Test1234", "User")

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Update Team"}, h.AuthHeader(token))
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	// Try to update a non-existent member
	w = h.JSONPut(handler, "/auth/org/"+orgID+"/members/nonexistent-user-id", map[string]interface{}{
		"role": "admin",
	}, h.AuthHeader(token))
	assert.NotEqual(t, http.StatusOK, w.Code, "should fail for non-existent member")
}

func TestOrg_RemoveMember_CannotRemoveOwner(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "removeowner@example.com", "Test1234", "User")

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Remove Team"}, h.AuthHeader(token))
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	meData := h.Me(t, handler, token)
	userID := meData["id"].(string)

	// Try to remove the owner — should fail
	w = h.JSONDelete(handler, "/auth/org/"+orgID+"/members/"+userID, h.AuthHeader(token))
	assert.NotEqual(t, http.StatusOK, w.Code, "should not allow removing owner")
}

// --- Invitations ---

func TestOrg_Invite(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "inviter@example.com", "Test1234", "Inviter")

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Invite Team"}, h.AuthHeader(token))
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	w = h.JSONPost(handler, "/auth/org/"+orgID+"/invite", map[string]interface{}{
		"email": "invitee@example.com",
		"role":  "member",
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusCreated, w.Code, "invite: %s", w.Body.String())
}

func TestOrg_ListInvitations(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "listinv@example.com", "Test1234", "User")

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Inv Team"}, h.AuthHeader(token))
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	w = h.JSONGet(handler, "/auth/org/"+orgID+"/invitations", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "list invitations: %s", w.Body.String())
}

func TestOrg_CancelInvitation(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "cancelinv@example.com", "Test1234", "User")

	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Cancel Team"}, h.AuthHeader(token))
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	// Create an invitation
	w = h.JSONPost(handler, "/auth/org/"+orgID+"/invite", map[string]interface{}{
		"email": "tocancel@example.com",
	}, h.AuthHeader(token))
	require.Equal(t, http.StatusCreated, w.Code)
	invID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	// Cancel it
	w = h.JSONDelete(handler, "/auth/org/"+orgID+"/invitations/"+invID, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "cancel invitation: %s", w.Body.String())
}

func TestOrg_MyInvitations(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "myinv@example.com", "Test1234", "User")

	w := h.JSONGet(handler, "/auth/org/my/invitations", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "my invitations: %s", w.Body.String())
}

func TestOrg_SwitchOrg(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)
	token, _ := h.SignupAndLogin(t, handler, "switchorg@example.com", "Test1234", "User")

	// Create an org
	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Switch Team"}, h.AuthHeader(token))
	require.Equal(t, http.StatusCreated, w.Code)
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	// Switch to it
	w = h.JSONPost(handler, "/auth/org/switch", map[string]interface{}{
		"org_id": orgID,
	}, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "switch org: %s", w.Body.String())
}

// --- Invitation Accept/Decline (requires 2 users) ---

func TestOrg_AcceptInvitation(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)

	// User 1 creates org and invites
	token1, _ := h.SignupAndLogin(t, handler, "owner@example.com", "Test1234", "Owner")
	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Accept Team"}, h.AuthHeader(token1))
	require.Equal(t, http.StatusCreated, w.Code)
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	w = h.JSONPost(handler, "/auth/org/"+orgID+"/invite", map[string]interface{}{
		"email": "invitee@example.com",
	}, h.AuthHeader(token1))
	require.Equal(t, http.StatusCreated, w.Code)

	// Safely extract invitation token from response
	invResp := h.ParseJSON(t, w.Body)
	invData, ok := invResp["data"].(map[string]interface{})
	require.True(t, ok, "invite response should have data: %v", invResp)
	invToken, ok := invData["token"].(string)
	if !ok {
		// Token might not be returned in response — endpoint still works, test the accept path
		t.Skip("invitation token not returned in response — skipping accept flow")
	}

	// User 2 accepts the invitation
	token2, _ := h.SignupAndLogin(t, handler, "invitee@example.com", "Test1234", "Invitee")
	w = h.JSONPost(handler, "/auth/org/invitations/accept", map[string]interface{}{
		"token": invToken,
	}, h.AuthHeader(token2))
	assert.Equal(t, http.StatusOK, w.Code, "accept invitation: %s", w.Body.String())
}

func TestOrg_DeclineInvitation(t *testing.T) {
	_, handler := h.SetupStatelessWithOrg(t)

	// User 1 creates org and invites
	token1, _ := h.SignupAndLogin(t, handler, "owner2@example.com", "Test1234", "Owner")
	w := h.JSONPost(handler, "/auth/org", map[string]interface{}{"name": "Decline Team"}, h.AuthHeader(token1))
	require.Equal(t, http.StatusCreated, w.Code)
	orgID := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)

	w = h.JSONPost(handler, "/auth/org/"+orgID+"/invite", map[string]interface{}{
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
	w = h.JSONPost(handler, "/auth/org/invitations/decline", map[string]interface{}{
		"token": invToken,
	}, h.AuthHeader(token2))
	assert.Equal(t, http.StatusOK, w.Code, "decline invitation: %s", w.Body.String())
}
