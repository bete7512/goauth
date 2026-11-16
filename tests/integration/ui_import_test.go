//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/models"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUI_InvitationImport(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Invitations: true})
	uiAdmin(t, env, "root@example.com")
	h.SignupUser(t, env.Handler, "member@example.com")
	b := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, b.SignIn("root@example.com", uiPassword).Code)
	assert.Contains(t, b.Get("/auth/ui/invitations").Body.String(), "Import a list")

	csvFile := "\ufeffemail,purpose\nada@example.com,beta\ngrace@example.com\nADA@example.com\nnot-an-email\nmember@example.com\n"
	w := b.Upload("/auth/ui/invitations/import", url.Values{"purpose": {"platform"}}, "file", "people.csv", []byte(csvFile))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, "3 sent, 2 skipped.")
	assert.Contains(t, body, "Repeats line 2.")

	list, _, err := env.Store.Invitation().Invitations().List(context.Background(), models.InvitationListOpts{ListingOpts: models.ListingOpts{Limit: 50}})
	require.NoError(t, err)
	purposes := map[string]string{}
	for _, invitation := range list {
		purposes[invitation.Email] = invitation.Purpose
	}
	assert.Equal(t, map[string]string{"ada@example.com": "beta", "grace@example.com": "platform", "member@example.com": "platform"}, purposes)

	// A pasted list works the same; an address with a pending invitation
	// for the same purpose is skipped.
	w = b.Post("/auth/ui/invitations/import", url.Values{"emails": {"grace@example.com\nlinus@example.com"}, "purpose": {"platform"}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "1 sent, 1 skipped.")

	assert.Equal(t, http.StatusUnprocessableEntity, b.Post("/auth/ui/invitations/import", url.Values{"emails": {""}}).Code)
	tooMany := strings.Repeat("x@example.com\n", 201)
	w = b.Post("/auth/ui/invitations/import", url.Values{"emails": {tooMany}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "at most 200")
}

func TestUI_OrganizationInvitations(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Organizations: true})
	b, _ := signedInAdmin(t, env)
	h.SignupUser(t, env.Handler, "owner@example.com")
	h.SignupUser(t, env.Handler, "member@example.com")
	w := b.Post("/auth/ui/orgs", url.Values{"name": {"Acme"}, "owner_email": {"owner@example.com"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	orgPath := strings.TrimSuffix(location(t, w), "?notice=org-created")
	orgID := strings.TrimPrefix(orgPath, "/auth/ui/orgs/")
	require.Equal(t, http.StatusSeeOther, b.Post(orgPath+"/members", url.Values{"email": {"member@example.com"}, "role": {"member"}}).Code)

	page := b.Get(orgPath + "/invitations").Body.String()
	assert.Contains(t, page, "Invite someone")
	assert.Contains(t, page, "Import a list")

	// A super admin may invite admins as well as members.
	w = b.Post(orgPath+"/invitations", url.Values{"email": {"ada@example.com"}, "role": {"admin"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	w = b.Post(orgPath+"/invitations", url.Values{"email": {"ada@example.com"}, "role": {"member"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "already invited")
	w = b.Post(orgPath+"/invitations", url.Values{"email": {"member@example.com"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "That user is already a member.")
	w = b.Post(orgPath+"/invitations", url.Values{"email": {"grace@example.com"}, "role": {"owner"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "invitations never grant ownership")

	w = b.Post(orgPath+"/invitations/import", url.Values{"emails": {"grace@example.com,admin\nlinus@example.com\nmember@example.com\nada@example.com"}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "2 sent, 2 skipped.")
	assert.Contains(t, w.Body.String(), `href="`+orgPath+`/invitations"`)

	list, _, err := env.Store.Organization().Invitations().ListByOrg(context.Background(), orgID, models.OrgInvitationListOpts{ListingOpts: models.ListingOpts{Limit: 20}})
	require.NoError(t, err)
	roles := map[string]string{}
	for _, inv := range list {
		roles[inv.Email] = inv.Role
	}
	assert.Equal(t, map[string]string{"ada@example.com": "admin", "grace@example.com": "admin", "linus@example.com": "member"}, roles)
}
