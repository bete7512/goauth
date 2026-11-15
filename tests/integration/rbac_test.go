//go:build integration

package integration_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRBAC_GlobalRoleGuardsRoutes(t *testing.T) {
	env := h.SetupRBAC(t, &rbac.Config{Roles: []rbac.Role{
		{Key: "viewer", Grants: []string{"*:read"}},
		{Key: "editor", Grants: []string{"*:read", "*:create", "*:update"}},
	}})
	env.Mux.Handle("/invoices/", env.Auth.RequireAuth(env.Authz.Resource("invoice")(h.OK)))
	env.Mux.Handle("POST /invoices/{id}/approve", env.Auth.RequireAuth(env.Authz.Require("invoice:approve")(h.OK)))

	userID, token := h.SignupUser(t, env.Mux, "viewer@example.com")

	w := h.JSONGet(env.Mux, "/invoices/1")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "no token")

	w = h.JSONGet(env.Mux, "/invoices/1", h.AuthHeader(token))
	require.Equal(t, http.StatusForbidden, w.Code, "no role yet: %s", w.Body.String())
	assert.Equal(t, "RBAC_PERMISSION_DENIED", h.ErrorCode(t, h.ParseJSON(t, w.Body)))

	require.NoError(t, env.Authz.Assign(t.Context(), userID, "viewer"))

	w = h.JSONGet(env.Mux, "/invoices/1", h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "viewer reads: %s", w.Body.String())
	w = h.JSONPost(env.Mux, "/invoices/", map[string]interface{}{}, h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code, "viewer cannot create")
	w = h.JSONPost(env.Mux, "/invoices/1/approve", map[string]interface{}{}, h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code, "viewer cannot approve")

	require.NoError(t, env.Authz.Assign(t.Context(), userID, "editor"))
	w = h.JSONPost(env.Mux, "/invoices/", map[string]interface{}{}, h.AuthHeader(token))
	assert.Equal(t, http.StatusOK, w.Code, "editor creates")
	w = h.JSONDelete(env.Mux, "/invoices/1", h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code, "editor cannot delete")

	require.NoError(t, env.Authz.Revoke(t.Context(), userID, "viewer"))
	require.NoError(t, env.Authz.Revoke(t.Context(), userID, "editor"))
	w = h.JSONGet(env.Mux, "/invoices/1", h.AuthHeader(token))
	assert.Equal(t, http.StatusForbidden, w.Code, "a revoked role stops working on the next request")
}

func rolesOf(t *testing.T, body map[string]interface{}) []string {
	t.Helper()
	data, _ := body["data"].(map[string]interface{})
	raw, _ := data["roles"].([]interface{})
	keys := make([]string, 0, len(raw))
	for _, item := range raw {
		role, _ := item.(map[string]interface{})
		key, _ := role["key"].(string)
		keys = append(keys, key)
	}
	return keys
}

func permissionsOf(t *testing.T, body map[string]interface{}) []string {
	t.Helper()
	data, _ := body["data"].(map[string]interface{})
	raw, _ := data["permissions"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		value, _ := item.(string)
		out = append(out, value)
	}
	return out
}

func TestRBAC_SuperAdminManagesGlobalRoles(t *testing.T) {
	env := h.SetupRBAC(t, nil)
	env.Mux.Handle("POST /reports/{id}/export", env.Auth.RequireAuth(env.Authz.Require("report:export")(h.OK)))

	adminID, adminToken := h.SignupUser(t, env.Mux, "root@example.com")
	h.MakeSuperAdmin(t, env.Store, adminID)
	userID, userToken := h.SignupUser(t, env.Mux, "analyst@example.com")

	// The catalog fills itself from the routes that were wired.
	w := h.JSONGet(env.Mux, "/auth/rbac/permissions", h.AuthHeader(adminToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var declared []string
	for _, item := range h.ParseJSON(t, w.Body)["data"].([]interface{}) {
		declared = append(declared, item.(map[string]interface{})["permission"].(string))
	}
	assert.Contains(t, declared, "report:export")
	assert.Contains(t, declared, "goauth.roles:write")

	w = h.JSONPost(env.Mux, "/auth/rbac/roles", map[string]interface{}{
		"key": "analyst", "name": "Analyst", "grants": []string{"report:*", "report:export"},
	}, h.AuthHeader(adminToken))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	created := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	assert.Equal(t, "analyst", created["key"])
	assert.Equal(t, false, created["system"])
	assert.ElementsMatch(t, []interface{}{"report:*", "report:export"}, created["grants"])

	w = h.JSONPost(env.Mux, "/auth/rbac/roles", map[string]interface{}{"key": "analyst", "name": "Again"}, h.AuthHeader(adminToken))
	assert.Equal(t, http.StatusConflict, w.Code, "duplicate key")
	w = h.JSONPost(env.Mux, "/auth/rbac/roles", map[string]interface{}{"key": "Bad Key", "name": "x"}, h.AuthHeader(adminToken))
	assert.Equal(t, http.StatusBadRequest, w.Code, "malformed key")
	w = h.JSONPost(env.Mux, "/auth/rbac/roles", map[string]interface{}{"key": "broken", "name": "x", "grants": []string{"not a grant"}}, h.AuthHeader(adminToken))
	assert.Equal(t, http.StatusBadRequest, w.Code, "malformed grant")
	w = h.JSONPost(env.Mux, "/auth/rbac/roles", map[string]interface{}{"key": "super_admin", "name": "x"}, h.AuthHeader(adminToken))
	assert.Equal(t, http.StatusConflict, w.Code, "reserved key")

	w = h.JSONGet(env.Mux, "/auth/rbac/roles?sort_field=key&sort_dir=asc", h.AuthHeader(adminToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	list := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})
	assert.EqualValues(t, 2, list["total"], "the built-in super admin role and the custom one")

	// The user has nothing yet.
	w = h.JSONPost(env.Mux, "/reports/7/export", map[string]interface{}{}, h.AuthHeader(userToken))
	assert.Equal(t, http.StatusForbidden, w.Code)

	w = h.JSONPut(env.Mux, "/auth/rbac/users/"+userID+"/roles", map[string]interface{}{"roles": []string{"analyst"}}, h.AuthHeader(adminToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, []string{"analyst"}, rolesOf(t, h.ParseJSON(t, w.Body)))

	w = h.JSONPost(env.Mux, "/reports/7/export", map[string]interface{}{}, h.AuthHeader(userToken))
	assert.Equal(t, http.StatusOK, w.Code, "role assigned: %s", w.Body.String())

	w = h.JSONGet(env.Mux, "/auth/me/permissions", h.AuthHeader(userToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	mine := h.ParseJSON(t, w.Body)
	assert.Equal(t, []string{"analyst"}, rolesOf(t, mine))
	assert.Equal(t, []string{"report:*", "report:export"}, permissionsOf(t, mine))

	w = h.JSONGet(env.Mux, "/auth/rbac/assignments?role=analyst", h.AuthHeader(adminToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.EqualValues(t, 1, h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["total"])

	// Narrowing the role takes effect on the next request.
	w = h.JSONPut(env.Mux, "/auth/rbac/roles/analyst", map[string]interface{}{"grants": []string{"report:read"}}, h.AuthHeader(adminToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.JSONPost(env.Mux, "/reports/7/export", map[string]interface{}{}, h.AuthHeader(userToken))
	assert.Equal(t, http.StatusForbidden, w.Code, "grant removed from the role")

	// Deleting the role removes it from everyone who held it.
	w = h.JSONDelete(env.Mux, "/auth/rbac/roles/analyst", h.AuthHeader(adminToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.JSONGet(env.Mux, "/auth/rbac/users/"+userID+"/roles", h.AuthHeader(adminToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Empty(t, rolesOf(t, h.ParseJSON(t, w.Body)))
	w = h.JSONGet(env.Mux, "/auth/rbac/roles/analyst", h.AuthHeader(adminToken))
	assert.Equal(t, http.StatusNotFound, w.Code)

	// The built-in role is read-only and cannot be assigned.
	w = h.JSONDelete(env.Mux, "/auth/rbac/roles/super_admin", h.AuthHeader(adminToken))
	assert.Equal(t, http.StatusConflict, w.Code)
	w = h.JSONPut(env.Mux, "/auth/rbac/users/"+userID+"/roles", map[string]interface{}{"roles": []string{"super_admin"}}, h.AuthHeader(adminToken))
	assert.Equal(t, http.StatusConflict, w.Code)
	w = h.JSONPut(env.Mux, "/auth/rbac/users/"+userID+"/roles", map[string]interface{}{"roles": []string{"no-such-role"}}, h.AuthHeader(adminToken))
	assert.Equal(t, http.StatusNotFound, w.Code)
	w = h.JSONPut(env.Mux, "/auth/rbac/users/"+userID+"/roles", map[string]interface{}{}, h.AuthHeader(adminToken))
	assert.Equal(t, http.StatusBadRequest, w.Code, "roles is required")
}

func TestRBAC_WithoutPermissionNothingCanBeManaged(t *testing.T) {
	env := h.SetupRBAC(t, &rbac.Config{Roles: []rbac.Role{{Key: "everything", Grants: []string{"*"}}}})
	userID, token := h.SignupUser(t, env.Mux, "plain@example.com")
	otherID, _ := h.SignupUser(t, env.Mux, "other@example.com")

	// "*" covers the application's permissions but never GoAuth's own.
	require.NoError(t, env.Authz.Assign(t.Context(), userID, "everything"))

	for _, attempt := range []struct {
		name string
		do   func() int
	}{
		{"catalog", func() int { return h.JSONGet(env.Mux, "/auth/rbac/permissions", h.AuthHeader(token)).Code }},
		{"list roles", func() int { return h.JSONGet(env.Mux, "/auth/rbac/roles", h.AuthHeader(token)).Code }},
		{"create role", func() int {
			return h.JSONPost(env.Mux, "/auth/rbac/roles", map[string]interface{}{"key": "x", "name": "X"}, h.AuthHeader(token)).Code
		}},
		{"read another user's roles", func() int {
			return h.JSONGet(env.Mux, "/auth/rbac/users/"+otherID+"/roles", h.AuthHeader(token)).Code
		}},
		{"give self a role", func() int {
			return h.JSONPut(env.Mux, "/auth/rbac/users/"+userID+"/roles", map[string]interface{}{"roles": []string{"everything"}}, h.AuthHeader(token)).Code
		}},
		{"list assignments", func() int { return h.JSONGet(env.Mux, "/auth/rbac/assignments", h.AuthHeader(token)).Code }},
	} {
		assert.Equal(t, http.StatusForbidden, attempt.do(), attempt.name)
	}

	// Users may always read what they hold themselves.
	w := h.JSONGet(env.Mux, "/auth/rbac/users/"+userID+"/roles", h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, []string{"everything"}, rolesOf(t, h.ParseJSON(t, w.Body)))

	assert.Equal(t, http.StatusUnauthorized, h.JSONGet(env.Mux, "/auth/rbac/roles").Code)
	assert.Equal(t, http.StatusUnauthorized, h.JSONGet(env.Mux, "/auth/me/permissions").Code)

	// Organization routes do not exist when Organizations is off.
	assert.Equal(t, http.StatusNotFound, h.JSONGet(env.Mux, "/auth/org/some-org/roles", h.AuthHeader(token)).Code)
}

// orgFixture is an organization with its owner, an admin and a plain member,
// each signed in to it.
type orgFixture struct {
	orgID                               string
	ownerID, adminID, memberID          string
	ownerToken, adminToken, memberToken string
	memberBaseToken                     string
}

func setupOrg(t *testing.T, env *h.RBACEnv, prefix string) orgFixture {
	t.Helper()
	var f orgFixture
	var ownerBase, adminBase string
	f.ownerID, ownerBase = h.SignupUser(t, env.Mux, prefix+"-owner@example.com")
	f.adminID, adminBase = h.SignupUser(t, env.Mux, prefix+"-admin@example.com")
	f.memberID, f.memberBaseToken = h.SignupUser(t, env.Mux, prefix+"-member@example.com")

	f.orgID = h.CreateOrg(t, env.Mux, ownerBase, prefix+" org")
	h.AddOrgMember(t, env.Store, f.orgID, f.adminID, types.OrgRoleAdmin)
	h.AddOrgMember(t, env.Store, f.orgID, f.memberID, types.OrgRoleMember)

	f.ownerToken = h.SwitchOrg(t, env.Mux, ownerBase, f.orgID)
	f.adminToken = h.SwitchOrg(t, env.Mux, adminBase, f.orgID)
	f.memberToken = h.SwitchOrg(t, env.Mux, f.memberBaseToken, f.orgID)
	return f
}

func TestRBAC_OrganizationRoles(t *testing.T) {
	env := h.SetupRBAC(t, &rbac.Config{Organizations: true})
	env.Mux.Handle("POST /invoices/{id}/approve", env.Auth.RequireAuth(env.Authz.Require("invoice:approve")(h.OK)))
	acme := setupOrg(t, env, "acme")
	globex := setupOrg(t, env, "globex")
	approve := func(token string) int {
		return h.JSONPost(env.Mux, "/invoices/7/approve", map[string]interface{}{}, h.AuthHeader(token)).Code
	}

	// Membership roles are built in: the owner and the admin hold every
	// permission of the application, a plain member holds none.
	assert.Equal(t, http.StatusOK, approve(acme.ownerToken))
	assert.Equal(t, http.StatusOK, approve(acme.adminToken))
	assert.Equal(t, http.StatusForbidden, approve(acme.memberToken))

	w := h.JSONGet(env.Mux, "/auth/me/permissions", h.AuthHeader(acme.adminToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	mine := h.ParseJSON(t, w.Body)
	assert.Equal(t, []string{"admin"}, rolesOf(t, mine))
	assert.Equal(t, []string{"*", "goauth.assignments:read", "goauth.roles:read"}, permissionsOf(t, mine))
	assert.Equal(t, acme.orgID, mine["data"].(map[string]interface{})["org_id"])

	// The owner creates a role and hands it to the member.
	base := "/auth/org/" + acme.orgID
	w = h.JSONPost(env.Mux, base+"/roles", map[string]interface{}{
		"key": "billing", "name": "Billing", "grants": []string{"invoice:*"},
	}, h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	w = h.JSONPut(env.Mux, base+"/members/"+acme.memberID+"/roles", map[string]interface{}{"roles": []string{"billing"}}, h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, []string{"member", "billing"}, rolesOf(t, h.ParseJSON(t, w.Body)), "the membership role is listed with the assigned one")

	assert.Equal(t, http.StatusOK, approve(acme.memberToken), "member now approves in acme")
	assert.Equal(t, http.StatusForbidden, approve(acme.memberBaseToken), "but not without being signed in to acme")

	// Roles do not cross organizations: the role is unknown in globex, and
	// the acme member is not a member there.
	w = h.JSONGet(env.Mux, "/auth/org/"+globex.orgID+"/roles/billing", h.AuthHeader(globex.ownerToken))
	assert.Equal(t, http.StatusNotFound, w.Code)
	w = h.JSONPut(env.Mux, "/auth/org/"+globex.orgID+"/members/"+acme.memberID+"/roles", map[string]interface{}{"roles": []string{}}, h.AuthHeader(globex.ownerToken))
	assert.Equal(t, http.StatusNotFound, w.Code, "not a member of globex")
	w = h.JSONGet(env.Mux, base+"/roles", h.AuthHeader(globex.ownerToken))
	assert.Equal(t, http.StatusForbidden, w.Code, "globex's owner has no say in acme")
	w = h.JSONGet(env.Mux, "/auth/org/"+globex.orgID+"/roles", h.AuthHeader(acme.ownerToken))
	assert.Equal(t, http.StatusForbidden, w.Code)

	// An admin can see roles but handing them out stays with the owner.
	w = h.JSONGet(env.Mux, base+"/roles", h.AuthHeader(acme.adminToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.EqualValues(t, 4, h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["total"], "owner, admin, member and billing")
	w = h.JSONPut(env.Mux, base+"/members/"+acme.adminID+"/roles", map[string]interface{}{"roles": []string{"billing"}}, h.AuthHeader(acme.adminToken))
	assert.Equal(t, http.StatusForbidden, w.Code)
	w = h.JSONPost(env.Mux, base+"/roles", map[string]interface{}{"key": "mine", "name": "Mine"}, h.AuthHeader(acme.adminToken))
	assert.Equal(t, http.StatusForbidden, w.Code)

	// Membership roles are implied, never assigned.
	w = h.JSONPut(env.Mux, base+"/members/"+acme.memberID+"/roles", map[string]interface{}{"roles": []string{"owner"}}, h.AuthHeader(acme.ownerToken))
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, "RBAC_ROLE_SYSTEM", h.ErrorCode(t, h.ParseJSON(t, w.Body)))
	w = h.JSONPost(env.Mux, base+"/roles", map[string]interface{}{"key": "admin", "name": "Admin"}, h.AuthHeader(acme.ownerToken))
	assert.Equal(t, http.StatusConflict, w.Code)

	w = h.JSONGet(env.Mux, base+"/role-assignments", h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.EqualValues(t, 1, h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["total"])

	// From code, for a named user, in a named organization.
	ctx := context.Background()
	assert.True(t, env.Authz.For(acme.memberID).Can(ctx, "invoice:approve", rbac.InOrg(acme.orgID)))
	assert.False(t, env.Authz.For(acme.memberID).Can(ctx, "invoice:approve", rbac.InOrg(globex.orgID)))
	assert.False(t, env.Authz.For(acme.memberID).Can(ctx, "invoice:approve"), "application-wide, the member holds nothing")
	assert.False(t, env.Authz.For("").Can(ctx, "invoice:approve", rbac.InOrg(acme.orgID)))
	var denied *types.GoAuthError
	require.ErrorAs(t, env.Authz.For(acme.memberID).Check(ctx, "project:delete", rbac.InOrg(acme.orgID)), &denied)
	assert.Equal(t, types.ErrRBACPermissionDenied, denied.Code)
	granted, err := env.Authz.For(acme.memberID).Permissions(ctx, rbac.InOrg(acme.orgID))
	require.NoError(t, err)
	assert.Equal(t, []string{"invoice:*"}, granted)
}

func TestRBAC_NobodyGrantsMoreThanTheyHold(t *testing.T) {
	env := h.SetupRBAC(t, &rbac.Config{Organizations: true})
	env.Authz.Define("invoice:read")
	acme := setupOrg(t, env, "acme")
	base := "/auth/org/" + acme.orgID

	// The owner delegates role management, limited to reading invoices.
	w := h.JSONPost(env.Mux, base+"/roles", map[string]interface{}{
		"key": "role-manager", "name": "Role manager",
		"grants": []string{"goauth.roles:*", "goauth.assignments:*", "invoice:read"},
	}, h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = h.JSONPut(env.Mux, base+"/members/"+acme.memberID+"/roles", map[string]interface{}{"roles": []string{"role-manager"}}, h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Within what the delegate holds: allowed.
	w = h.JSONPost(env.Mux, base+"/roles", map[string]interface{}{"key": "reader", "name": "Reader", "grants": []string{"invoice:read"}}, h.AuthHeader(acme.memberToken))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = h.JSONPut(env.Mux, base+"/members/"+acme.adminID+"/roles", map[string]interface{}{"roles": []string{"reader"}}, h.AuthHeader(acme.memberToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Beyond it: refused, whichever way it is attempted.
	for name, body := range map[string]map[string]interface{}{
		"wider action":    {"key": "writer", "name": "W", "grants": []string{"invoice:*"}},
		"other resource":  {"key": "projects", "name": "P", "grants": []string{"project:read"}},
		"everything":      {"key": "all", "name": "A", "grants": []string{"*"}},
		"goauth wildcard": {"key": "sys", "name": "S", "grants": []string{"goauth.*:*"}},
	} {
		w = h.JSONPost(env.Mux, base+"/roles", body, h.AuthHeader(acme.memberToken))
		assert.Equal(t, http.StatusForbidden, w.Code, name)
		assert.Equal(t, "RBAC_GRANT_NOT_HELD", h.ErrorCode(t, h.ParseJSON(t, w.Body)), name)
	}
	w = h.JSONPut(env.Mux, base+"/roles/reader", map[string]interface{}{"grants": []string{"invoice:read", "invoice:approve"}}, h.AuthHeader(acme.memberToken))
	assert.Equal(t, http.StatusForbidden, w.Code, "widening an existing role")

	// A role that grants more than the delegate holds can be neither given,
	// changed nor taken away by the delegate.
	w = h.JSONPost(env.Mux, base+"/roles", map[string]interface{}{"key": "approver", "name": "Approver", "grants": []string{"invoice:approve"}}, h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	w = h.JSONPut(env.Mux, base+"/members/"+acme.memberID+"/roles", map[string]interface{}{"roles": []string{"role-manager", "approver"}}, h.AuthHeader(acme.memberToken))
	assert.Equal(t, http.StatusForbidden, w.Code, "self-assignment of a stronger role")
	w = h.JSONDelete(env.Mux, base+"/roles/approver", h.AuthHeader(acme.memberToken))
	assert.Equal(t, http.StatusForbidden, w.Code)
	w = h.JSONPut(env.Mux, base+"/roles/approver", map[string]interface{}{"grants": []string{}}, h.AuthHeader(acme.memberToken))
	assert.Equal(t, http.StatusForbidden, w.Code, "emptying a stronger role")

	w = h.JSONPut(env.Mux, base+"/members/"+acme.adminID+"/roles", map[string]interface{}{"roles": []string{"reader", "approver"}}, h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.JSONPut(env.Mux, base+"/members/"+acme.adminID+"/roles", map[string]interface{}{"roles": []string{"reader"}}, h.AuthHeader(acme.memberToken))
	assert.Equal(t, http.StatusForbidden, w.Code, "taking a stronger role away")
}

func TestRBAC_RolesEndWithTheMembership(t *testing.T) {
	env := h.SetupRBAC(t, &rbac.Config{Organizations: true})
	env.Authz.Define("invoice:approve")
	acme := setupOrg(t, env, "acme")
	ctx := context.Background()
	base := "/auth/org/" + acme.orgID

	w := h.JSONPost(env.Mux, base+"/roles", map[string]interface{}{"key": "billing", "name": "Billing", "grants": []string{"invoice:*"}}, h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.NoError(t, env.Authz.Assign(ctx, acme.memberID, "billing", rbac.InOrg(acme.orgID)))
	subject := env.Authz.For(acme.memberID)
	require.True(t, subject.Can(ctx, "invoice:approve", rbac.InOrg(acme.orgID)))

	// The member leaves and rejoins. The membership row is replaced directly,
	// so nothing tells the module: the old assignment row is still there.
	members := env.Store.Organization().Members()
	require.NoError(t, members.DeleteByOrgAndUser(ctx, acme.orgID, acme.memberID))
	assert.False(t, subject.Can(ctx, "invoice:approve", rbac.InOrg(acme.orgID)), "not a member")
	h.AddOrgMember(t, env.Store, acme.orgID, acme.memberID, types.OrgRoleMember)

	leftover, err := env.Store.RBAC().Assignments().ListByUser(ctx, acme.memberID, []models.RoleScopeRef{{Type: models.RoleScopeOrg, ID: acme.orgID}})
	require.NoError(t, err)
	require.Len(t, leftover, 1, "the stale row exists")
	assert.False(t, subject.Can(ctx, "invoice:approve", rbac.InOrg(acme.orgID)), "a new membership does not revive old roles")

	// Assigning again replaces the stale row.
	require.NoError(t, env.Authz.Assign(ctx, acme.memberID, "billing", rbac.InOrg(acme.orgID)))
	assert.True(t, subject.Can(ctx, "invoice:approve", rbac.InOrg(acme.orgID)))

	// Removing a member through the API cleans the assignments up.
	w = h.JSONDelete(env.Mux, base+"/members/"+acme.memberID, h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.False(t, subject.Can(ctx, "invoice:approve", rbac.InOrg(acme.orgID)))
	require.Eventually(t, func() bool {
		rows, err := env.Store.RBAC().Assignments().ListByUser(ctx, acme.memberID, []models.RoleScopeRef{{Type: models.RoleScopeOrg, ID: acme.orgID}})
		return err == nil && len(rows) == 0
	}, 2*time.Second, 20*time.Millisecond, "assignments are removed when the member is")

	// A role cannot be given to someone who is not a member.
	err = env.Authz.Assign(ctx, acme.memberID, "billing", rbac.InOrg(acme.orgID))
	var authErr *types.GoAuthError
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, types.ErrOrgMemberNotFound, authErr.Code)
}

func TestRBAC_CallbacksAndOwningOrganization(t *testing.T) {
	type invoice struct{ orgID, author string }
	invoices := map[string]invoice{}
	var denials []string

	env := h.SetupRBAC(t, &rbac.Config{
		Organizations: true,
		Roles:         []rbac.Role{{Key: "member", Scope: rbac.ScopeOrg, Grants: []string{"invoice:read", "invoice:approve"}}},
		Decide: func(_ context.Context, c rbac.Check) rbac.Decision {
			if c.Permission == "report:export" {
				return rbac.Deny("Exports need the Pro plan")
			}
			return rbac.Keep
		},
		OnDeny: func(w http.ResponseWriter, _ *http.Request, c rbac.Check) {
			denials = append(denials, c.Permission)
			http.Error(w, "denied: "+c.Permission, http.StatusTeapot)
		},
	})
	invoiceOf := func(r *http.Request) invoice { return invoices[r.PathValue("id")] }
	ownOrg := rbac.OrgFrom(func(r *http.Request) (string, error) {
		found, ok := invoices[r.PathValue("id")]
		if !ok {
			return "", &types.GoAuthError{Code: types.ErrCustom, Message: "no such invoice", StatusCode: http.StatusNotFound}
		}
		return found.orgID, nil
	})
	env.Mux.Handle("GET /invoices/{id}", env.Auth.RequireAuth(env.Authz.Require("invoice:read", ownOrg)(h.OK)))
	env.Mux.Handle("POST /invoices/{id}/approve", env.Auth.RequireAuth(env.Authz.Require("invoice:approve", ownOrg,
		rbac.OnlyIf(func(_ context.Context, c rbac.Check) bool { return invoiceOf(c.Request).author != c.UserID }))(h.OK)))
	env.Mux.Handle("PUT /invoices/{id}", env.Auth.RequireAuth(env.Authz.Require("invoice:update", ownOrg,
		rbac.AllowIf(func(_ context.Context, c rbac.Check) bool { return invoiceOf(c.Request).author == c.UserID }))(h.OK)))
	env.Mux.Handle("POST /reports/export", env.Auth.RequireAuth(env.Authz.Require("report:export")(h.OK)))
	env.Mux.Handle("GET /broken", env.Auth.RequireAuth(env.Authz.Require("invoice:read",
		rbac.OnlyIf(func(context.Context, rbac.Check) bool { panic("boom") }))(h.OK)))

	acme := setupOrg(t, env, "acme")
	globex := setupOrg(t, env, "globex")
	invoices["a1"] = invoice{orgID: acme.orgID, author: acme.memberID}
	invoices["a2"] = invoice{orgID: acme.orgID, author: acme.adminID}
	invoices["g1"] = invoice{orgID: globex.orgID, author: globex.memberID}
	call := func(method, path, token string) int {
		switch method {
		case http.MethodGet:
			return h.JSONGet(env.Mux, path, h.AuthHeader(token)).Code
		case http.MethodPut:
			return h.JSONPut(env.Mux, path, map[string]interface{}{}, h.AuthHeader(token)).Code
		default:
			return h.JSONPost(env.Mux, path, map[string]interface{}{}, h.AuthHeader(token)).Code
		}
	}

	// OrgFrom: the check runs in the organization that owns the invoice, so
	// a member of acme cannot read globex's invoice by guessing its ID.
	assert.Equal(t, http.StatusOK, call(http.MethodGet, "/invoices/a1", acme.memberToken))
	assert.Equal(t, http.StatusTeapot, call(http.MethodGet, "/invoices/g1", acme.memberToken))
	assert.Equal(t, http.StatusOK, call(http.MethodGet, "/invoices/g1", globex.memberToken))
	assert.Equal(t, http.StatusNotFound, call(http.MethodGet, "/invoices/nope", acme.memberToken), "the resolver's own error is sent as is")

	// OnlyIf: holding the permission is not enough for one's own invoice.
	assert.Equal(t, http.StatusTeapot, call(http.MethodPost, "/invoices/a1/approve", acme.memberToken))
	assert.Equal(t, http.StatusOK, call(http.MethodPost, "/invoices/a2/approve", acme.memberToken))

	// AllowIf: authors edit their own invoice without holding the permission.
	assert.Equal(t, http.StatusOK, call(http.MethodPut, "/invoices/a1", acme.memberToken))
	assert.Equal(t, http.StatusTeapot, call(http.MethodPut, "/invoices/a2", acme.memberToken))

	// Decide overrules roles, even the owner's "*".
	denials = nil
	assert.Equal(t, http.StatusTeapot, call(http.MethodPost, "/reports/export", acme.ownerToken))
	assert.Equal(t, []string{"report:export"}, denials, "OnDeny wrote the response")
	var authErr *types.GoAuthError
	require.ErrorAs(t, env.Authz.For(acme.ownerID).Check(context.Background(), "report:export", rbac.InOrg(acme.orgID)), &authErr)
	assert.Equal(t, "Exports need the Pro plan", authErr.Message)

	// A condition that panics refuses the request.
	assert.Equal(t, http.StatusTeapot, call(http.MethodGet, "/broken", acme.memberToken))
}

func TestRBAC_SubscribersCanRefuseAnAssignment(t *testing.T) {
	env := h.SetupRBAC(t, &rbac.Config{Roles: []rbac.Role{{Key: "admin", Grants: []string{"*"}}, {Key: "viewer", Grants: []string{"*:read"}}}})
	env.Auth.On(types.EventBeforeRBACRoleAssign, func(_ context.Context, event *types.Event) error {
		data, ok := types.EventDataAs[*types.RBACAssignmentEventData](event)
		if ok && data.RoleKey == "admin" {
			return errors.New("your plan allows no more admins")
		}
		return nil
	})
	assigned := h.RecordEvents(env.Auth, types.EventRBACRoleAssigned)
	userID, _ := h.SignupUser(t, env.Mux, "seat@example.com")
	ctx := context.Background()

	err := env.Authz.Assign(ctx, userID, "admin")
	var authErr *types.GoAuthError
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, types.ErrRBACAssignmentRefused, authErr.Code)
	assert.Equal(t, "your plan allows no more admins", authErr.Message)
	assert.False(t, env.Authz.For(userID).Can(ctx, "invoice:delete"))

	require.NoError(t, env.Authz.Assign(ctx, userID, "viewer"))
	event := h.Nth(t, assigned, 1, func(data *types.RBACAssignmentEventData) bool { return data.UserID == userID })
	assert.Equal(t, "viewer", event.RoleKey)
	assert.Equal(t, models.RoleScopeGlobal, event.ScopeType)
}

// An organization's owner holds everything inside it, and anyone can create
// an organization. Routes about the whole platform must count application-wide
// roles only, and /me/permissions must report the same thing a check finds.
func TestRBAC_OrganizationRolesStayInsideTheOrganization(t *testing.T) {
	env := h.SetupRBAC(t, &rbac.Config{Organizations: true, Roles: []rbac.Role{{Key: "support", Scope: rbac.ScopeGlobal, Grants: []string{"tenant:*"}}}})
	env.Mux.Handle("POST /tenants/{id}/suspend", env.Auth.RequireAuth(env.Authz.Require("tenant:suspend", rbac.Global())(h.OK)))
	env.Mux.Handle("POST /unscoped", env.Auth.RequireAuth(env.Authz.Require("tenant:suspend")(h.OK)))
	acme := setupOrg(t, env, "acme")
	globex := setupOrg(t, env, "globex")
	suspend := func(token string) int {
		return h.JSONPost(env.Mux, "/tenants/"+globex.orgID+"/suspend", map[string]interface{}{}, h.AuthHeader(token)).Code
	}

	assert.Equal(t, http.StatusForbidden, suspend(acme.ownerToken), "an owner's * does not reach a platform route")
	assert.Equal(t, http.StatusOK, h.JSONPost(env.Mux, "/unscoped", map[string]interface{}{}, h.AuthHeader(acme.ownerToken)).Code,
		"without Global the same permission is satisfied inside the owner's own organization")

	// Platform staff hold the role application-wide, whatever they are signed in to.
	staffID, staffToken := h.SignupUser(t, env.Mux, "staff@example.com")
	require.NoError(t, env.Authz.Assign(t.Context(), staffID, "support"))
	assert.Equal(t, http.StatusOK, suspend(staffToken))

	// A global role cannot be handed out inside an organization, and an
	// organization's owner cannot hand out application-wide roles.
	w := h.JSONPut(env.Mux, "/auth/org/"+acme.orgID+"/members/"+acme.memberID+"/roles", map[string]interface{}{"roles": []string{"support"}}, h.AuthHeader(acme.ownerToken))
	assert.Equal(t, http.StatusNotFound, w.Code, "the role does not exist in the organization scope")
	w = h.JSONPut(env.Mux, "/auth/rbac/users/"+acme.memberID+"/roles", map[string]interface{}{"roles": []string{"support"}}, h.AuthHeader(acme.ownerToken))
	assert.Equal(t, http.StatusForbidden, w.Code)

	// What staff hold inside an organization they are not a member of.
	w = h.JSONGet(env.Mux, "/auth/me/permissions?org_id="+acme.orgID, h.AuthHeader(staffToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	mine := h.ParseJSON(t, w.Body)
	assert.Equal(t, []string{"support"}, rolesOf(t, mine))
	assert.Equal(t, []string{"tenant:*"}, permissionsOf(t, mine))

	// And what a member of one organization holds in another: nothing.
	w = h.JSONGet(env.Mux, "/auth/me/permissions?org_id="+globex.orgID, h.AuthHeader(acme.ownerToken))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	mine = h.ParseJSON(t, w.Body)
	assert.Empty(t, rolesOf(t, mine))
	assert.Empty(t, permissionsOf(t, mine))
}
