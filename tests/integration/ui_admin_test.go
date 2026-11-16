//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/modules/ui"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedInAdmin creates a super admin and a browser signed in as them.
func signedInAdmin(t *testing.T, env *h.UIEnv) (*h.Browser, string) {
	t.Helper()
	id := uiAdmin(t, env, "root@example.com")
	b := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, b.SignIn("root@example.com", uiPassword).Code)
	return b, id
}

func location(t *testing.T, w interface{ Header() http.Header }) string {
	t.Helper()
	return w.Header().Get("Location")
}

// Every area appears in the sidebar; the ones whose module is missing are
// shown disabled with the module to register, and their pages say so.
func TestUI_SidebarShowsEveryAreaAndExplainsMissingModules(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{})
	b, _ := signedInAdmin(t, env)
	page := b.Get("/auth/ui").Body.String()
	for _, area := range []string{"Organizations", "Invitations", "Teams", "Roles", "Permissions", "OIDC clients", "Audit log", "Settings"} {
		assert.Contains(t, page, "<span>"+area+"</span>", area)
	}
	assert.Contains(t, page, `data-tip="Register the organization module to use this"`)
	assert.Contains(t, page, `data-tip="Register the idp (identity provider) module to use this"`)
	assert.Contains(t, page, `href="/auth/ui/settings"`, "settings is always available")
	assert.NotContains(t, page, `href="/auth/ui/orgs"`, "a disabled area is not a link")

	for path, module := range map[string]string{"/auth/ui/orgs": "organization", "/auth/ui/teams": "team", "/auth/ui/invitations": "invitation", "/auth/ui/clients": "idp", "/auth/ui/roles": "rbac", "/auth/ui/permissions": "rbac", "/auth/ui/audit": "audit"} {
		w := b.Get(path)
		assert.Equal(t, http.StatusNotFound, w.Code, path)
		assert.Contains(t, w.Body.String(), "Register the "+module, path)
	}

	w := b.Get("/auth/ui/settings")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "After 5 failed attempts")
	assert.Contains(t, w.Body.String(), "stateless")
}

func TestUI_CreateUserAndSupportActions(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Session: true})
	b, _ := signedInAdmin(t, env)

	w := b.Get("/auth/ui/users/new")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "At least 4 characters", "the password policy is shown")

	w = b.Post("/auth/ui/users", url.Values{"email": {"new@example.com"}, "name": {"New Person"}, "password": {"x"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "too short")
	assert.Contains(t, w.Body.String(), `value="new@example.com"`)
	assert.NotContains(t, w.Body.String(), `value="x"`, "a rejected password is not echoed back")

	w = b.Post("/auth/ui/users", url.Values{"email": {"root@example.com"}, "password": {uiPassword}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "email already in use")

	w = b.Post("/auth/ui/users", url.Values{"email": {"new@example.com"}, "name": {"New Person"}, "password": {"Created1"}, "email_verified": {"on"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	userPath := strings.TrimSuffix(location(t, w), "?notice=user-created")
	userID := strings.TrimPrefix(userPath, "/auth/ui/users/")
	created, err := env.Store.Core().Users().FindByID(t.Context(), userID)
	require.NoError(t, err)
	assert.True(t, created.EmailVerified)
	assert.NotEmpty(t, created.Username, "a username is generated as at signup")

	// The new user can sign in with that password.
	_, refresh := h.Login(t, env.Handler, "new@example.com", "Created1")

	// Lockout: the console shows it and can lift it.
	locked := time.Now().Add(time.Hour)
	created.LockedUntil, created.FailedLoginAttempts = &locked, 5
	require.NoError(t, env.Store.Core().Users().Update(t.Context(), created))
	w = b.Get(userPath)
	assert.Contains(t, w.Body.String(), "This account is locked after 5 failed sign-in attempts")
	w = b.Post(userPath+"/unlock", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code)
	unlocked, err := env.Store.Core().Users().FindByID(t.Context(), userID)
	require.NoError(t, err)
	assert.Nil(t, unlocked.LockedUntil)
	assert.Zero(t, unlocked.FailedLoginAttempts)

	// Sessions are listed on the Security tab and can be ended.
	w = b.Get(userPath + "/security")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "/sessions/")
	sessionID := regexp.MustCompile(`/sessions/([^/]+)/revoke`).FindStringSubmatch(w.Body.String())[1]
	w = b.Post(userPath+"/sessions/"+sessionID+"/revoke", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, http.StatusUnauthorized, h.JSONPost(env.Handler, "/auth/refresh", map[string]interface{}{"refresh_token": refresh}).Code, "the session's refresh token is dead")

	// Set a password: the old one stops working, the new one works.
	w = b.Post(userPath+"/password", url.Values{"password": {"z"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	w = b.Post(userPath+"/password", url.Values{"password": {"Replaced2"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, http.StatusUnauthorized, h.JSONPost(env.Handler, "/auth/login", map[string]interface{}{"email": "new@example.com", "password": "Created1"}).Code)
	access, _ := h.Login(t, env.Handler, "new@example.com", "Replaced2")

	// Sign out everywhere invalidates current tokens.
	require.Equal(t, http.StatusOK, h.JSONGet(env.Handler, "/auth/me", h.AuthHeader(access)).Code)
	w = b.Post(userPath+"/sign-out", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, http.StatusUnauthorized, h.JSONGet(env.Handler, "/auth/me", h.AuthHeader(access)).Code)

	// Emails need the notification module; the page says so.
	w = b.Post(userPath+"/reset-email", url.Values{})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "Register the notification module")
}

func TestUI_SecurityTabManagesSignInMethods(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{OAuth: true, Passkeys: true, TwoFactor: true, Audit: true})
	b, _ := signedInAdmin(t, env)
	userID, _ := h.SignupUser(t, env.Handler, "person@example.com")
	ctx := context.Background()

	account := &models.Account{ID: uuid.NewString(), UserID: userID, Provider: "github", ProviderAccountID: "gh-123", Type: "oauth", RealmID: "default"}
	require.NoError(t, env.Store.OAuth().Accounts().Create(ctx, account))
	passkey := &models.PasskeyCredential{ID: uuid.NewString(), UserID: userID, CredentialID: []byte(uuid.NewString()), PublicKey: []byte("key"), Name: "YubiKey 5"}
	require.NoError(t, env.Store.Passkeys().Passkeys().Create(ctx, passkey))
	require.NoError(t, env.Store.TwoFactorAuth().TwoFactor().Create(ctx, &models.TwoFactor{ID: uuid.NewString(), UserID: userID, Secret: "s", Enabled: true, Verified: true, Method: "totp"}))
	require.NoError(t, env.Store.TwoFactorAuth().BackupCodes().CreateBatch(ctx, []*models.BackupCode{{ID: uuid.NewString(), UserID: userID, Code: "c1"}, {ID: uuid.NewString(), UserID: userID, Code: "c2"}}))

	base := "/auth/ui/users/" + userID
	w := b.Get(base + "/security")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	page := w.Body.String()
	assert.Contains(t, page, "github")
	assert.Contains(t, page, "gh-123")
	assert.Contains(t, page, "YubiKey 5")
	assert.Contains(t, page, "2 backup codes left")
	assert.Contains(t, page, "stateless tokens", "no session list for the stateless strategy")

	require.Equal(t, http.StatusSeeOther, b.Post(base+"/accounts/"+account.ID+"/unlink", url.Values{}).Code)
	accounts, err := env.Store.OAuth().Accounts().FindByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, accounts)

	require.Equal(t, http.StatusSeeOther, b.Post(base+"/passkeys/"+passkey.ID+"/delete", url.Values{}).Code)
	list, err := env.Store.Passkeys().Passkeys().ListByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, list)

	require.Equal(t, http.StatusSeeOther, b.Post(base+"/2fa/reset", url.Values{}).Code)
	_, err = env.Store.TwoFactorAuth().TwoFactor().GetByUserID(ctx, userID)
	assert.Error(t, err, "two-factor settings are gone")
	codes, err := env.Store.TwoFactorAuth().BackupCodes().GetByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, codes)

	// Another user's identifiers are refused.
	otherID, _ := h.SignupUser(t, env.Handler, "other@example.com")
	foreign := &models.Account{ID: uuid.NewString(), UserID: otherID, Provider: "github", ProviderAccountID: "gh-999", Type: "oauth", RealmID: "default"}
	require.NoError(t, env.Store.OAuth().Accounts().Create(ctx, foreign))
	w = b.Post(base+"/accounts/"+foreign.ID+"/unlink", url.Values{})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	kept, err := env.Store.OAuth().Accounts().FindByID(ctx, foreign.ID)
	require.NoError(t, err)
	assert.Equal(t, otherID, kept.UserID)

	// Every change is recorded with the administrator as the actor.
	require.Eventually(t, func() bool {
		return strings.Count(b.Get(base+"/activity").Body.String(), "admin.user.updated") >= 3
	}, 2*time.Second, 20*time.Millisecond)
}

func TestUI_ManageOrganizations(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Organizations: true, RBAC: &rbac.Config{Organizations: true}})
	b, _ := signedInAdmin(t, env)
	ownerID, _ := h.SignupUser(t, env.Handler, "owner@example.com")
	memberID, _ := h.SignupUser(t, env.Handler, "member@example.com")
	ctx := context.Background()

	w := b.Post("/auth/ui/orgs", url.Values{"name": {"Acme"}, "owner_email": {"ghost@example.com"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "No user has that email address.")

	w = b.Post("/auth/ui/orgs", url.Values{"name": {"Acme Corp"}, "owner_email": {"owner@example.com"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	orgPath := strings.TrimSuffix(location(t, w), "?notice=org-created")
	orgID := strings.TrimPrefix(orgPath, "/auth/ui/orgs/")
	org, err := env.Store.Organization().Organizations().FindByID(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, ownerID, org.OwnerID)
	assert.Equal(t, "acme-corp", org.Slug)

	w = b.Get("/auth/ui/orgs?q=acme", map[string]string{"HX-Request": "true", "HX-Target": "orgs-table"})
	assert.True(t, strings.HasPrefix(strings.TrimSpace(w.Body.String()), `<div id="orgs-table">`))
	assert.Contains(t, w.Body.String(), "Acme Corp")

	// Members: add, change role, protect the owner, remove.
	w = b.Post(orgPath+"/members", url.Values{"email": {"member@example.com"}, "role": {"member"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	w = b.Post(orgPath+"/members", url.Values{"email": {"member@example.com"}, "role": {"member"}})
	assert.Contains(t, w.Body.String(), "already a member")
	w = b.Post(orgPath+"/members/"+memberID+"/role", url.Values{"role": {"admin"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	member, err := env.Store.Organization().Members().FindByOrgAndUser(ctx, orgID, memberID)
	require.NoError(t, err)
	assert.Equal(t, "admin", member.Role)
	w = b.Post(orgPath+"/members/"+ownerID+"/remove", url.Values{})
	assert.Contains(t, w.Body.String(), "Transfer ownership first")
	w = b.Post(orgPath+"/members/"+ownerID+"/role", url.Values{"role": {"member"}})
	assert.Contains(t, w.Body.String(), "Transfer ownership first")

	// Organization roles for a member.
	w = b.Post(orgPath+"/roles", url.Values{"key": {"billing"}, "name": {"Billing"}, "grants": {"invoice:*"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	w = b.Get(orgPath + "/members/" + memberID)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `name="roles" value="billing"`)
	w = b.Post(orgPath+"/members/"+memberID+"/roles", url.Values{"roles": {"billing"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	w = b.Get(orgPath + "/roles/billing")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "member@example.com", "the role page lists who holds it")

	// Transfer ownership; the previous owner becomes an admin.
	w = b.Post(orgPath+"/owner", url.Values{"user_id": {memberID}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	org, err = env.Store.Organization().Organizations().FindByID(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, memberID, org.OwnerID)
	previous, err := env.Store.Organization().Members().FindByOrgAndUser(ctx, orgID, ownerID)
	require.NoError(t, err)
	assert.Equal(t, "admin", previous.Role)

	// Suspend and restore.
	require.Equal(t, http.StatusSeeOther, b.Post(orgPath+"/status", url.Values{"active": {"false"}}).Code)
	org, _ = env.Store.Organization().Organizations().FindByID(ctx, orgID)
	assert.False(t, org.Active)
	assert.Contains(t, b.Get(orgPath).Body.String(), "Suspended")
	require.Equal(t, http.StatusSeeOther, b.Post(orgPath+"/status", url.Values{"active": {"true"}}).Code)

	// Invitations are listed and can be cancelled.
	invitation := &models.OrgInvitation{ID: uuid.NewString(), OrgID: orgID, Email: "invitee@example.com", Role: "member", InviterID: ownerID, Token: uuid.NewString(), Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, env.Store.Organization().Invitations().Create(ctx, invitation))
	assert.Contains(t, b.Get(orgPath+"/invitations").Body.String(), "invitee@example.com")
	require.Equal(t, http.StatusSeeOther, b.Post(orgPath+"/invitations/"+invitation.ID+"/cancel", url.Values{}).Code)

	// The user's Access tab shows the membership.
	assert.Contains(t, b.Get("/auth/ui/users/"+memberID+"/access").Body.String(), "Acme Corp")

	// Delete needs the slug, and removes members and invitations with it.
	again := &models.OrgInvitation{ID: uuid.NewString(), OrgID: orgID, Email: "late@example.com", Role: "member", InviterID: ownerID, Token: uuid.NewString(), Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, env.Store.Organization().Invitations().Create(ctx, again))
	w = b.Post(orgPath+"/delete", url.Values{"confirm": {"wrong"}})
	assert.Contains(t, w.Body.String(), "Type the organization")
	w = b.Post(orgPath+"/delete", url.Values{"confirm": {"acme-corp"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	_, err = env.Store.Organization().Organizations().FindByID(ctx, orgID)
	assert.ErrorIs(t, err, models.ErrNotFound)
	memberships, err := env.Store.Organization().Members().ListByUser(ctx, memberID)
	require.NoError(t, err)
	assert.Empty(t, memberships, "memberships go with the organization")
	_, err = env.Store.Organization().Invitations().FindByID(ctx, again.ID)
	assert.ErrorIs(t, err, models.ErrNotFound, "invitations go with the organization")
}

func TestUI_EditRolesAndSeePermissions(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{RBAC: &rbac.Config{Roles: []rbac.Role{{Key: "viewer", Name: "Viewer", Grants: []string{"*:read"}}}}})
	b, _ := signedInAdmin(t, env)
	authz := envAuthz(t, env)
	authz.Define("invoice:approve", "Approve invoices")
	authz.Define("invoice:read")
	userID, _ := h.SignupUser(t, env.Handler, "analyst@example.com")

	require.Equal(t, http.StatusSeeOther, b.Post("/auth/ui/roles", url.Values{"key": {"approver"}, "name": {"Approver"}, "grants": {"invoice:read"}}).Code)
	require.NoError(t, authz.Assign(t.Context(), userID, "approver"))

	w := b.Get("/auth/ui/roles/approver")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "analyst@example.com", "holders are listed")

	w = b.Post("/auth/ui/roles/approver", url.Values{"name": {"Invoice approver"}, "grants": {"invoice:read\ninvoice:approve"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.True(t, authz.For(userID).Can(t.Context(), "invoice:approve"), "the edit applies on the next check")

	w = b.Post("/auth/ui/roles/approver", url.Values{"name": {"X"}, "grants": {"not a grant"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "not a grant", "what was typed is kept")

	w = b.Get("/auth/ui/roles/viewer")
	assert.Contains(t, w.Body.String(), "defined in code")
	assert.NotContains(t, w.Body.String(), `action="/auth/ui/roles/viewer"`, "a role from code has no edit form")

	w = b.Get("/auth/ui/permissions")
	require.Equal(t, http.StatusOK, w.Code)
	page := w.Body.String()
	assert.Contains(t, page, "invoice:approve")
	assert.Contains(t, page, "Approve invoices")
	assert.Contains(t, page, "Invoice approver")
	assert.Contains(t, page, "Super admin", "wildcard roles are listed once at the top")
}

func TestUI_PlatformInvitations(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Invitations: true})
	b, _ := signedInAdmin(t, env)
	otherAdmin := uiAdmin(t, env, "second@example.com")
	ctx := context.Background()
	require.NoError(t, env.Store.Invitation().Invitations().Create(ctx, &models.Invitation{ID: uuid.NewString(), Email: "from-other@example.com", Purpose: "beta", InviterID: otherAdmin, Token: uuid.NewString(), Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}))

	w := b.Post("/auth/ui/invitations", url.Values{"email": {"guest@example.com"}, "purpose": {""}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	w = b.Get("/auth/ui/invitations")
	page := w.Body.String()
	assert.Contains(t, page, "guest@example.com")
	assert.Contains(t, page, "from-other@example.com", "invitations from every administrator are listed")

	id := regexp.MustCompile(`/invitations/([^/]+)/cancel`).FindStringSubmatch(page)[1]
	require.Equal(t, http.StatusSeeOther, b.Post("/auth/ui/invitations/"+id+"/cancel", url.Values{}).Code)
	w = b.Get("/auth/ui/invitations?status=pending")
	assert.Equal(t, 1, strings.Count(w.Body.String(), "/cancel\""), "one pending invitation is left")
}

func TestUI_ManageOIDCClients(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{IDP: true})
	b, _ := signedInAdmin(t, env)

	w := b.Post("/auth/ui/clients", url.Values{"name": {"Grafana"}, "redirect_uris": {"https://grafana.example.com/login/generic_oauth"}, "scopes": {"openid profile email"}, "require_pkce": {"on"}})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	page := w.Body.String()
	assert.Contains(t, page, "Client secret")
	secret := regexp.MustCompile(`<div class="secret"><code>([^<]+)</code>`).FindStringSubmatch(page)[1]
	assert.NotEmpty(t, secret)
	id := regexp.MustCompile(`action="/auth/ui/clients/([^/"]+)"`).FindStringSubmatch(page)[1]

	w = b.Get("/auth/ui/clients/" + id)
	assert.NotContains(t, w.Body.String(), secret, "the secret is shown once")
	assert.Contains(t, w.Body.String(), "http://localhost:8080/auth/oidc", "the issuer is shown")

	w = b.Post("/auth/ui/clients/"+id, url.Values{"name": {"Grafana prod"}, "redirect_uris": {"not a url"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	w = b.Post("/auth/ui/clients/"+id, url.Values{"name": {"Grafana prod"}, "redirect_uris": {"https://grafana.example.com/login/generic_oauth"}, "require_pkce": {"on"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Contains(t, b.Get("/auth/ui/clients").Body.String(), "Grafana prod")

	w = b.Post("/auth/ui/clients/"+id+"/rotate", url.Values{})
	require.Equal(t, http.StatusOK, w.Code)
	rotated := regexp.MustCompile(`<div class="secret"><code>([^<]+)</code>`).FindStringSubmatch(w.Body.String())[1]
	assert.NotEqual(t, secret, rotated)

	require.Equal(t, http.StatusSeeOther, b.Post("/auth/ui/clients/"+id+"/delete", url.Values{}).Code)
	assert.Equal(t, http.StatusNotFound, b.Get("/auth/ui/clients/"+id).Code)
}

// Everything above is for super admins only.
func TestUI_AdministrationPagesNeedASuperAdmin(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{UI: &ui.Config{UserPages: true}, Organizations: true, Invitations: true, IDP: true, RBAC: &rbac.Config{}})
	userID, _ := h.SignupUser(t, env.Handler, "plain@example.com")
	b := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, b.SignIn("plain@example.com", uiPassword).Code)
	for _, path := range []string{"/auth/ui/users/new", "/auth/ui/users/" + userID + "/security", "/auth/ui/orgs", "/auth/ui/orgs/new", "/auth/ui/invitations", "/auth/ui/clients", "/auth/ui/roles", "/auth/ui/permissions", "/auth/ui/settings"} {
		assert.Equal(t, http.StatusForbidden, b.Get(path).Code, path)
	}
	for _, path := range []string{"/auth/ui/users", "/auth/ui/orgs", "/auth/ui/clients", "/auth/ui/invitations", "/auth/ui/users/" + userID + "/sign-out", "/auth/ui/users/" + userID + "/password"} {
		assert.Equal(t, http.StatusForbidden, b.Post(path, url.Values{"email": {"x@example.com"}, "password": {"Whatever1"}, "name": {"x"}}).Code, path)
	}
	_ = types.RBACModule
}

func TestUI_OverviewCharts(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Audit: true})
	b, _ := signedInAdmin(t, env)
	h.SignupUser(t, env.Handler, "someone@example.com")
	page := b.Get("/auth/ui").Body.String()
	for _, title := range []string{"Sign-ups", "Sign-ins", "Failed sign-ins"} {
		assert.Contains(t, page, ">"+title+"</h2>", title)
	}
	assert.Contains(t, page, `class="chart-mark"`, "today's sign-ups draw a bar")
	assert.Contains(t, page, "Show as a table")

	plain := h.SetupUI(t, h.UIOptions{})
	b, _ = signedInAdmin(t, plain)
	page = b.Get("/auth/ui").Body.String()
	assert.Contains(t, page, ">Sign-ups</h2>")
	assert.NotContains(t, page, ">Sign-ins</h2>", "activity charts need the audit module")
}
