//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"sort"
	"testing"

	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTeam(t *testing.T, env *h.RBACEnv, token, orgID, name, parentID string) string {
	t.Helper()
	w := h.JSONPost(env.Mux, "/auth/org/"+orgID+"/teams", map[string]interface{}{"name": name, "parent_id": parentID}, h.AuthHeader(token))
	require.Equal(t, http.StatusCreated, w.Code, "create team %s: %s", name, w.Body.String())
	return h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)
}

func addTeamMember(t *testing.T, env *h.RBACEnv, token, orgID, teamID, userID, role string) {
	t.Helper()
	w := h.JSONPost(env.Mux, "/auth/org/"+orgID+"/teams/"+teamID+"/members", map[string]interface{}{"user_id": userID, "role": role}, h.AuthHeader(token))
	require.Equal(t, http.StatusCreated, w.Code, "add member: %s", w.Body.String())
}

func TestTeam_NestingAndWhoManagesWhat(t *testing.T) {
	env := h.SetupRBAC(t, &rbac.Config{Organizations: true, Teams: true})
	f := setupOrg(t, env, "acme")
	base := "/auth/org/" + f.orgID + "/teams"

	// Only the owner and admins create top-level teams.
	w := h.JSONPost(env.Mux, base, map[string]interface{}{"name": "Rogue"}, h.AuthHeader(f.memberToken))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, string(types.ErrTeamForbidden), h.ErrorCode(t, h.ParseJSON(t, w.Body)))

	eng := createTeam(t, env, f.adminToken, f.orgID, "Engineering", "")
	w = h.JSONPost(env.Mux, base, map[string]interface{}{"name": "Engineering"}, h.AuthHeader(f.ownerToken))
	assert.Equal(t, http.StatusConflict, w.Code, "the slug is taken")

	// A lead manages the team and everything beneath it.
	addTeamMember(t, env, f.adminToken, f.orgID, eng, f.memberID, "lead")
	backend := createTeam(t, env, f.memberToken, f.orgID, "Backend", eng)
	db := createTeam(t, env, f.memberToken, f.orgID, "Databases", backend)

	// Nesting has a limit: five levels.
	parent := db
	for _, name := range []string{"L4", "L5", "L6"} {
		w = h.JSONPost(env.Mux, base, map[string]interface{}{"name": name, "parent_id": parent}, h.AuthHeader(f.ownerToken))
		if name == "L6" {
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Equal(t, string(types.ErrTeamTooDeep), h.ErrorCode(t, h.ParseJSON(t, w.Body)))
			break
		}
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		parent = h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["id"].(string)
	}

	// The tree lists each team after its parent.
	w = h.JSONGet(env.Mux, base+"?tree=true", h.AuthHeader(f.memberToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	list := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["list"].([]interface{})
	var names []string
	for _, item := range list {
		names = append(names, item.(map[string]interface{})["name"].(string))
	}
	assert.Equal(t, []string{"Engineering", "Backend", "Databases", "L4", "L5"}, names)

	// A team cannot move beneath itself, and a team with sub-teams cannot be deleted.
	w = h.JSONPost(env.Mux, base+"/"+backend+"/move", map[string]interface{}{"parent_id": db}, h.AuthHeader(f.ownerToken))
	assert.Equal(t, string(types.ErrTeamInvalidParent), h.ErrorCode(t, h.ParseJSON(t, w.Body)))
	w = h.JSONDelete(env.Mux, base+"/"+backend, h.AuthHeader(f.ownerToken))
	assert.Equal(t, http.StatusConflict, w.Code)

	// Moving a sub-tree rewrites everything beneath it.
	w = h.JSONPost(env.Mux, base+"/"+backend+"/move", map[string]interface{}{"parent_id": ""}, h.AuthHeader(f.ownerToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.JSONGet(env.Mux, base+"/"+db, h.AuthHeader(f.ownerToken))
	moved := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	assert.Equal(t, float64(1), moved["depth"])
	assert.Equal(t, []interface{}{backend}, moved["ancestors"])
	// The lead of Engineering no longer manages Backend, now at the top.
	w = h.JSONPut(env.Mux, base+"/"+backend, map[string]interface{}{"name": "Backend 2"}, h.AuthHeader(f.memberToken))
	assert.Equal(t, http.StatusForbidden, w.Code)

	// Only members of the organization can join a team.
	outsiderID, _ := h.SignupUser(t, env.Mux, "outsider@example.com")
	w = h.JSONPost(env.Mux, base+"/"+eng+"/members", map[string]interface{}{"user_id": outsiderID}, h.AuthHeader(f.ownerToken))
	assert.Equal(t, http.StatusNotFound, w.Code)

	// Outsiders see nothing; members may leave.
	_, outsiderToken := h.SignupUser(t, env.Mux, "outsider2@example.com")
	assert.Equal(t, http.StatusNotFound, h.JSONGet(env.Mux, base, h.AuthHeader(outsiderToken)).Code)
	assert.Equal(t, http.StatusOK, h.JSONDelete(env.Mux, base+"/"+eng+"/members/"+f.memberID, h.AuthHeader(f.memberToken)).Code)
}

func TestTeam_RolesFlowDownTheTree(t *testing.T) {
	env := h.SetupRBAC(t, &rbac.Config{Organizations: true, Teams: true, Roles: []rbac.Role{
		{Key: "editor", Grants: []string{"project:*"}},
	}})
	env.Mux.Handle("DELETE /teams/{teamId}/projects", env.Auth.RequireAuth(env.Authz.Require("project:delete", rbac.TeamParam("teamId"))(h.OK)))
	f := setupOrg(t, env, "flow")
	eng := createTeam(t, env, f.ownerToken, f.orgID, "Engineering", "")
	backend := createTeam(t, env, f.ownerToken, f.orgID, "Backend", eng)
	design := createTeam(t, env, f.ownerToken, f.orgID, "Design", "")

	del := func(token, teamID string) int {
		return h.JSONDelete(env.Mux, "/teams/"+teamID+"/projects", h.AuthHeader(token)).Code
	}
	assert.Equal(t, http.StatusOK, del(f.adminToken, backend), "organization roles apply in every team")
	assert.Equal(t, http.StatusForbidden, del(f.memberToken, backend))

	// A role on a team applies to it and everything beneath, never above or beside.
	w := h.JSONPut(env.Mux, "/auth/org/"+f.orgID+"/teams/"+eng+"/members/"+f.memberID+"/roles", map[string]interface{}{"roles": []string{"editor"}}, h.AuthHeader(f.ownerToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, http.StatusOK, del(f.memberToken, eng))
	assert.Equal(t, http.StatusOK, del(f.memberToken, backend))
	assert.Equal(t, http.StatusForbidden, del(f.memberToken, design))

	// Leads hold every permission of the application's own beneath them.
	leadID, leadBase := h.SignupUser(t, env.Mux, "lead@example.com")
	h.AddOrgMember(t, env.Store, f.orgID, leadID, types.OrgRoleMember)
	leadToken := h.SwitchOrg(t, env.Mux, leadBase, f.orgID)
	addTeamMember(t, env, f.ownerToken, f.orgID, design, leadID, "lead")
	assert.Equal(t, http.StatusOK, del(leadToken, design))
	assert.Equal(t, http.StatusForbidden, del(leadToken, eng))

	// TeamsWhere answers the list-route question.
	ids, all, err := env.Authz.For(f.memberID).TeamsWhere(context.Background(), f.orgID, "project:delete")
	require.NoError(t, err)
	assert.False(t, all)
	sort.Strings(ids)
	want := []string{eng, backend}
	sort.Strings(want)
	assert.Equal(t, want, ids)
	_, all, err = env.Authz.For(f.adminID).TeamsWhere(context.Background(), f.orgID, "project:delete")
	require.NoError(t, err)
	assert.True(t, all)

	// A team named under another organization's URL is not found.
	other := setupOrg(t, env, "other")
	w = h.JSONGet(env.Mux, "/auth/org/"+other.orgID+"/teams/"+eng+"/members/"+f.memberID+"/roles", h.AuthHeader(other.ownerToken))
	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// Team roles end with the organization membership.
	require.NoError(t, env.Store.Organization().Members().DeleteByOrgAndUser(context.Background(), f.orgID, f.memberID))
	memberAgain := h.AddOrgMember(t, env.Store, f.orgID, f.memberID, types.OrgRoleMember)
	require.NotEmpty(t, memberAgain)
	token := h.SwitchOrg(t, env.Mux, f.memberBaseToken, f.orgID)
	assert.Equal(t, http.StatusForbidden, del(token, backend), "rejoining does not bring the team role back")

	// Team scopes cannot define roles: they are the organization's.
	w = h.JSONGet(env.Mux, "/auth/org/"+f.orgID+"/teams/"+eng+"/roles", h.AuthHeader(f.ownerToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
