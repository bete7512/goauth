//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUI_ManageTeams(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Teams: true, RBAC: &rbac.Config{Organizations: true, Teams: true, Roles: []rbac.Role{{Key: "editor", Grants: []string{"project:*"}}}}})
	b, _ := signedInAdmin(t, env)
	h.SignupUser(t, env.Handler, "owner@example.com")
	memberID, _ := h.SignupUser(t, env.Handler, "member@example.com")
	ctx := context.Background()

	w := b.Post("/auth/ui/orgs", url.Values{"name": {"Acme"}, "owner_email": {"owner@example.com"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	orgPath := strings.TrimSuffix(location(t, w), "?notice=org-created")
	require.Equal(t, http.StatusSeeOther, b.Post(orgPath+"/members", url.Values{"email": {"member@example.com"}, "role": {"member"}}).Code)

	// The sidebar's Teams page lists organizations; the organization has a Teams tab.
	assert.Contains(t, b.Get("/auth/ui").Body.String(), `href="/auth/ui/teams"`)
	page := b.Get("/auth/ui/teams").Body.String()
	if !assert.Contains(t, page, "Acme") {
		i := strings.Index(page, `<main`)
		t.Logf("teams: %s", page[i:min(i+1500, len(page))])
	}
	orgPage := b.Get(orgPath).Body.String()
	if !assert.Contains(t, orgPage, `href="`+orgPath+`/teams"`) {
		i := strings.Index(orgPage, `class="tabs"`)
		t.Logf("tabs: %s", orgPage[i:min(i+900, len(orgPage))])
	}

	w = b.Post(orgPath+"/teams", url.Values{"name": {"Engineering"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	engPath := strings.TrimSuffix(location(t, w), "?notice=team-created")
	engID := strings.TrimPrefix(engPath, orgPath+"/teams/")
	w = b.Post(orgPath+"/teams", url.Values{"name": {"Backend"}, "parent_id": {engID}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	backendPath := strings.TrimSuffix(location(t, w), "?notice=team-created")
	backendID := strings.TrimPrefix(backendPath, orgPath+"/teams/")

	w = b.Post(orgPath+"/teams", url.Values{"name": {"Engineering"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "the slug is taken")

	page = b.Get(orgPath + "/teams").Body.String()
	assert.Less(t, strings.Index(page, ">Engineering<"), strings.Index(page, ">Backend<"), "the tree lists parents first")
	assert.Contains(t, page, "tree-row depth-1")

	// Members: add, make lead, give a team role, remove.
	require.Equal(t, http.StatusSeeOther, b.Post(engPath+"/members", url.Values{"user_id": {memberID}, "role": {"member"}}).Code)
	require.Equal(t, http.StatusSeeOther, b.Post(engPath+"/members/"+memberID+"/role", url.Values{"role": {"lead"}}).Code)
	row, err := env.Store.Team().Members().FindByTeamAndUser(ctx, engID, memberID)
	require.NoError(t, err)
	assert.Equal(t, models.TeamRoleLead, row.Role)

	page = b.Get(engPath + "/members/" + memberID).Body.String()
	if !assert.Contains(t, page, `value="editor"`) {
		i := strings.Index(page, `id="roles"`)
		t.Logf("roles: %s", page[max(i-200, 0):min(i+1200, len(page))])
	}
	assert.Contains(t, page, "Team lead")
	require.Equal(t, http.StatusSeeOther, b.Post(engPath+"/members/"+memberID+"/roles", url.Values{"roles": {"editor"}}).Code)
	assignments, err := env.Store.RBAC().Assignments().ListByUser(ctx, memberID, []models.RoleScopeRef{{Type: models.RoleScopeTeam, ID: engID}})
	require.NoError(t, err)
	require.Len(t, assignments, 1)

	// Deleting a team with sub-teams is refused; moving the sub-team out frees it.
	w = b.Post(engPath+"/delete", nil)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "beneath this team first")
	require.Equal(t, http.StatusSeeOther, b.Post(backendPath+"/move", url.Values{"parent_id": {""}}).Code)
	moved, err := env.Store.Team().Teams().FindByID(ctx, backendID)
	require.NoError(t, err)
	assert.Equal(t, 0, moved.Depth)
	require.Equal(t, http.StatusSeeOther, b.Post(engPath+"/members/"+memberID+"/remove", nil).Code)
	require.Equal(t, http.StatusSeeOther, b.Post(engPath+"/delete", nil).Code)
	_, err = env.Store.Team().Teams().FindByID(ctx, engID)
	assert.ErrorIs(t, err, models.ErrNotFound)
}
