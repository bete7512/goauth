//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/modules/ui"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const uiPassword = "Test1234"

// uiAdmin creates a super admin and returns the user's ID.
func uiAdmin(t *testing.T, env *h.UIEnv, email string) string {
	t.Helper()
	id, _ := h.SignupUser(t, env.Handler, email)
	h.MakeSuperAdmin(t, env.Store, id)
	return id
}

func TestUI_AdminSignsInAndUsesTheConsole(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Audit: true})
	uiAdmin(t, env, "root@example.com")
	b := h.NewBrowser(t, env.Handler)

	// Signed-out visitors are sent to sign in, and back afterwards.
	w := b.Get("/auth/ui/users?q=root")
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/auth/ui/login?next=%2Fauth%2Fui%2Fusers%3Fq%3Droot", w.Header().Get("Location"))

	w = b.Get(w.Header().Get("Location"))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `name="next" value="/auth/ui/users?q=root"`)

	w = b.Post("/auth/ui/login", url.Values{"email": {"root@example.com"}, "password": {uiPassword}, "next": {"/auth/ui/users?q=root"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui/users?q=root", w.Header().Get("Location"))
	assert.NotEmpty(t, b.Cookies["goauth_access_session"], "the console signs in with the application's own cookies")

	w = b.Get("/auth/ui")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, "Overview")
	assert.Contains(t, body, "Audit log", "the audit page is offered because the audit module is registered")
	assert.NotContains(t, body, `/admin/roles"`, "no roles page without the rbac module")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Header().Get("Content-Security-Policy"), "script-src 'self'")
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))

	w = b.Get("/auth/ui/audit")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Apply retention")
	w = b.Post("/auth/ui/audit/cleanup", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Contains(t, b.Get(w.Header().Get("Location")).Body.String(), "older than the retention period were deleted")

	w = b.Post("/auth/ui/logout", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/auth/ui/login?notice=signed-out", w.Header().Get("Location"))
	assert.Empty(t, b.Cookies, "every credential cookie is cleared")
	assert.Equal(t, http.StatusSeeOther, b.Get("/auth/ui").Code)
}

func TestUI_Assets(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{})
	b := h.NewBrowser(t, env.Handler)
	page := b.Get("/auth/ui/login").Body.String()
	for _, name := range []string{"app.css", "htmx.min.js", "app.js"} {
		start := strings.Index(page, "/auth/ui/assets/"+name+"?v=")
		require.GreaterOrEqual(t, start, 0, name)
		link := page[start : start+strings.IndexByte(page[start:], '"')]
		w := b.Get(link)
		require.Equal(t, http.StatusOK, w.Code, name)
		assert.Contains(t, w.Header().Get("Cache-Control"), "immutable", name)
		assert.NotEmpty(t, w.Body.Bytes(), name)

		w = b.Get("/auth/ui/assets/" + name + "?v=stale")
		assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"), "an old version is revalidated")
	}
	assert.Equal(t, http.StatusNotFound, b.Get("/auth/ui/assets/missing.js").Code)
	assert.Equal(t, http.StatusNotFound, b.Get("/auth/ui/assets/..%2Fmodule.go").Code)
}

func TestUI_NonAdminsAreTurnedAwayUnlessUserPagesAreOn(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{})
	h.SignupUser(t, env.Handler, "plain@example.com")
	b := h.NewBrowser(t, env.Handler)
	w := b.SignIn("plain@example.com", uiPassword)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "This console is for administrators.")
	assert.Empty(t, b.Cookies, "no cookies are set for a user the console turned away")
	assert.Equal(t, http.StatusNotFound, b.Get("/auth/ui/account").Code, "no account page unless UserPages is on")

	env = h.SetupUI(t, h.UIOptions{UI: &ui.Config{UserPages: true, Title: "Acme"}, Audit: true})
	h.SignupUser(t, env.Handler, "plain@example.com")
	b = h.NewBrowser(t, env.Handler)
	w = b.SignIn("plain@example.com", uiPassword)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui/account", w.Header().Get("Location"))
	w = b.Get("/auth/ui/account")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "plain@example.com")
	assert.Contains(t, w.Body.String(), "Acme")
	assert.NotContains(t, w.Body.String(), "/auth/ui/users", "no admin navigation for a plain user")

	w = b.Get("/auth/ui/users")
	assert.Equal(t, http.StatusForbidden, w.Code)

	// A plain user cannot be sent to an admin page after signing in.
	b = h.NewBrowser(t, env.Handler)
	w = b.Post("/auth/ui/login", url.Values{"email": {"plain@example.com"}, "password": {uiPassword}, "next": {"/auth/ui/users"}})
	assert.Equal(t, "/auth/ui/account", w.Header().Get("Location"))
}

func TestUI_SignInFailures(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{})
	uiAdmin(t, env, "root@example.com")
	b := h.NewBrowser(t, env.Handler)

	for name, form := range map[string]url.Values{
		"wrong password": {"email": {"root@example.com"}, "password": {"nope"}},
		"unknown user":   {"email": {"ghost@example.com"}, "password": {uiPassword}},
	} {
		w := b.Post("/auth/ui/login", form)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code, name)
		assert.Contains(t, w.Body.String(), "The email or password is incorrect.", name)
	}
	w := b.Post("/auth/ui/login", url.Values{"email": {"root@example.com"}})
	assert.Contains(t, w.Body.String(), "Enter your email and password.")
	assert.Empty(t, b.Cookies)

	// Only paths inside the console are accepted as a destination.
	for _, next := range []string{"https://evil.example", "//evil.example/auth/ui", "/auth/ui/../../x", "/auth/other", "/auth/ui/login", "/auth/ui\\evil"} {
		b = h.NewBrowser(t, env.Handler)
		w = b.Post("/auth/ui/login", url.Values{"email": {"root@example.com"}, "password": {uiPassword}, "next": {next}})
		require.Equal(t, http.StatusSeeOther, w.Code, next)
		assert.Equal(t, "/auth/ui", w.Header().Get("Location"), next)
	}
}

func TestUI_CrossSiteFormsAreRefused(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{CSRF: true})
	// The JSON signup route needs a CSRF token here, so the users are
	// created directly.
	h.CreateUser(t, env.Store, "root@example.com", uiPassword, true)
	victim := h.CreateUser(t, env.Store, "victim@example.com", uiPassword, false)
	b := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, b.SignIn("root@example.com", uiPassword).Code, "same-origin forms work with the CSRF module registered")

	b.Site = "cross-site"
	w := b.Post("/auth/ui/users/"+victim+"/delete", url.Values{})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "came from another site")

	b.Site = ""
	w = b.Post("/auth/ui/users/"+victim+"/delete", url.Values{}, map[string]string{"Origin": "https://evil.example"})
	assert.Equal(t, http.StatusForbidden, w.Code, "an Origin of another site is refused too")

	b.Site = "same-origin"
	assert.Equal(t, http.StatusOK, b.Get("/auth/ui/users/"+victim).Code, "the user still exists")
	assert.Equal(t, http.StatusSeeOther, b.Post("/auth/ui/users/"+victim+"/delete", url.Values{}).Code)
	assert.Equal(t, http.StatusNotFound, b.Get("/auth/ui/users/"+victim).Code)
}

func TestUI_RefusesToStartWithoutCookies(t *testing.T) {
	for _, mode := range []types.AuthMode{types.AuthModeBearer} {
		a, err := auth.New(&config.Config{
			Storage:   h.NewStore(t),
			Security:  types.SecurityConfig{JwtSecretKey: strings.Repeat("k", 32), EncryptionKey: strings.Repeat("e", 32), AuthMode: mode},
			RateLimit: &config.RateLimitModuleConfig{Disabled: true},
			Migration: config.MigrationConfig{Auto: true},
		})
		require.NoError(t, err)
		require.NoError(t, a.Use(ui.New(nil)))
		err = a.Initialize(context.Background())
		require.Error(t, err, mode)
		assert.Contains(t, err.Error(), "cookie", mode)
	}
}

func TestUI_ManageUsers(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Audit: true})
	adminID := uiAdmin(t, env, "root@example.com")
	targetID, _ := h.SignupUser(t, env.Handler, "target@example.com")
	h.SignupUser(t, env.Handler, "other@example.com")
	b := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, b.SignIn("root@example.com", uiPassword).Code)

	// A full page, then only the table when htmx asks for it.
	w := b.Get("/auth/ui/users")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<!doctype html>")
	assert.Contains(t, w.Body.String(), "target@example.com")

	w = b.Get("/auth/ui/users?q=target", map[string]string{"HX-Request": "true", "HX-Target": "users-table"})
	require.Equal(t, http.StatusOK, w.Code)
	fragment := w.Body.String()
	assert.NotContains(t, fragment, "<!doctype html>", "a search returns only the table")
	assert.True(t, strings.HasPrefix(strings.TrimSpace(fragment), `<div id="users-table">`))
	assert.Contains(t, fragment, "target@example.com")
	assert.NotContains(t, fragment, "other@example.com")
	assert.Contains(t, w.Header().Values("Vary"), "HX-Request")

	w = b.Get("/auth/ui/users?q=nobody-matches")
	assert.Contains(t, w.Body.String(), "No users match")

	// Edit: every field of the form is applied, unticked boxes clear flags.
	form := url.Values{
		"name": {"Target Person"}, "first_name": {"Target"}, "last_name": {"Person"},
		"email": {"target@example.com"}, "username": {"target"}, "phone_number": {"+15550001"},
		"email_verified": {"on"},
	}
	w = b.Post("/auth/ui/users/"+targetID, form)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui/users/"+targetID+"?notice=saved", w.Header().Get("Location"))
	user, err := env.Store.Core().Users().FindByID(t.Context(), targetID)
	require.NoError(t, err)
	assert.Equal(t, "Target Person", user.Name)
	assert.Equal(t, "target", user.Username)
	assert.True(t, user.EmailVerified)
	assert.False(t, user.Active, "an unticked Active box deactivates the user")
	assert.False(t, user.IsSuperAdmin)

	w = b.Get("/auth/ui/users/" + targetID + "?notice=saved")
	assert.Contains(t, w.Body.String(), "Changes saved.")
	assert.Contains(t, w.Body.String(), "Disabled")

	// Notices come from a fixed list; the URL cannot inject text.
	w = b.Get("/auth/ui/users/" + targetID + "?notice=%3Cscript%3Ealert(1)%3C/script%3E")
	assert.NotContains(t, w.Body.String(), "alert(1)")

	form.Set("email", "not-an-email")
	w = b.Post("/auth/ui/users/"+targetID, form)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "Enter a valid email address.")
	assert.Contains(t, w.Body.String(), `value="not-an-email"`, "what was typed is kept")

	// Administrators cannot lock themselves out.
	w = b.Post("/auth/ui/users/"+adminID, url.Values{"email": {"root@example.com"}, "active": {"on"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "remove your own administrator access")
	w = b.Post("/auth/ui/users/"+adminID+"/delete", url.Values{})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	me, err := env.Store.Core().Users().FindByID(t.Context(), adminID)
	require.NoError(t, err)
	assert.True(t, me.IsSuperAdmin)
	assert.True(t, me.Active)

	// Delete someone else.
	w = b.Post("/auth/ui/users/"+targetID+"/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/auth/ui/users?notice=user-deleted", w.Header().Get("Location"))
	assert.Equal(t, http.StatusNotFound, b.Get("/auth/ui/users/"+targetID).Code)
	assert.Equal(t, http.StatusNotFound, b.Get("/auth/ui/users/no-such-id").Code)

	// The changes were made as the administrator and are audited.
	require.Eventually(t, func() bool {
		return strings.Contains(b.Get("/auth/ui/audit").Body.String(), "admin.user.deleted")
	}, 2*time.Second, 20*time.Millisecond)
	w = b.Get("/auth/ui/audit?action=admin.user.deleted", map[string]string{"HX-Request": "true", "HX-Target": "audit-table"})
	assert.True(t, strings.HasPrefix(strings.TrimSpace(w.Body.String()), `<div id="audit-table">`))
	assert.Contains(t, w.Body.String(), adminID)
}

// htmx requests that need a sign-in get HX-Redirect, so htmx loads the
// sign-in page instead of swapping it into the table.
func TestUI_HTMXRequestsAreRedirectedWhole(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{})
	b := h.NewBrowser(t, env.Handler)
	w := b.Get("/auth/ui/users?q=x", map[string]string{"HX-Request": "true", "HX-Target": "users-table"})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/auth/ui/login?next=%2Fauth%2Fui%2Fusers%3Fq%3Dx", w.Header().Get("HX-Redirect"))
	assert.Empty(t, w.Body.String())
}

func TestUI_ManageRoles(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{RBAC: &rbac.Config{Roles: []rbac.Role{{Key: "viewer", Name: "Viewer", Grants: []string{"*:read"}}}}})
	uiAdmin(t, env, "root@example.com")
	targetID, _ := h.SignupUser(t, env.Handler, "analyst@example.com")
	b := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, b.SignIn("root@example.com", uiPassword).Code)

	w := b.Get("/auth/ui/roles")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Viewer")
	assert.Contains(t, w.Body.String(), "Super admin")

	w = b.Post("/auth/ui/roles", url.Values{"key": {"analyst"}, "name": {"Analyst"}, "grants": {"report:*\nreport:export, invoice:read"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	w = b.Get("/auth/ui/roles?notice=role-created")
	assert.Contains(t, w.Body.String(), "Role created.")
	assert.Contains(t, w.Body.String(), "report:export")

	w = b.Post("/auth/ui/roles", url.Values{"key": {"Bad Key"}, "name": {"Broken"}, "grants": {"invoice"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), `value="Broken"`, "the form keeps what was typed")

	// Give the user roles from their Access tab.
	w = b.Get("/auth/ui/users/" + targetID + "/access")
	require.Contains(t, w.Body.String(), `name="roles" value="analyst"`)
	assert.NotContains(t, w.Body.String(), `name="roles" value="super_admin"`, "an implied role is not offered")
	w = b.Post("/auth/ui/users/"+targetID+"/roles", url.Values{"roles": {"analyst", "viewer"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	granted, err := envAuthz(t, env).For(targetID).Permissions(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []string{"*:read", "invoice:read", "report:*", "report:export"}, granted)

	w = b.Post("/auth/ui/users/"+targetID+"/roles", url.Values{"roles": {"super_admin"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	w = b.Post("/auth/ui/roles/viewer/delete", url.Values{})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "roles defined in code cannot be deleted")
	w = b.Post("/auth/ui/roles/analyst/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	granted, err = envAuthz(t, env).For(targetID).Permissions(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []string{"*:read"}, granted, "deleting a role takes it away from everyone")
}

func envAuthz(t *testing.T, env *h.UIEnv) *rbac.Module {
	t.Helper()
	module, err := env.Auth.GetModule("rbac")
	require.NoError(t, err)
	authz, ok := module.(*rbac.Module)
	require.True(t, ok)
	return authz
}

func TestUI_TwoFactorSignIn(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{TwoFactor: true})
	uiAdmin(t, env, "root@example.com")
	token, _ := h.Login(t, env.Handler, "root@example.com", uiPassword)
	w := h.JSONPost(env.Handler, "/auth/2fa/setup", nil, h.AuthHeader(token))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	secret := h.ParseJSON(t, w.Body)["data"].(map[string]interface{})["secret"].(string)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, h.JSONPost(env.Handler, "/auth/2fa/verify", map[string]interface{}{"code": code}, h.AuthHeader(token)).Code)

	b := h.NewBrowser(t, env.Handler)
	w = b.SignIn("root@example.com", uiPassword)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	page := w.Body.String()
	assert.Contains(t, page, "Two-factor authentication")
	assert.Empty(t, b.Cookies, "no credentials before the second factor")
	start := strings.Index(page, `name="temp_token" value="`) + len(`name="temp_token" value="`)
	require.Greater(t, start, len(`name="temp_token" value="`))
	tempToken := page[start : start+strings.IndexByte(page[start:], '"')]

	w = b.Post("/auth/ui/login/2fa", url.Values{"temp_token": {tempToken}, "code": {"000000"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "That code is not valid.")
	assert.Contains(t, w.Body.String(), tempToken, "a wrong code keeps the sign-in going")

	// The setup code's time step is spent, so use the next one.
	next, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	require.NoError(t, err)
	w = b.Post("/auth/ui/login/2fa", url.Values{"temp_token": {tempToken}, "code": {next}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui", w.Header().Get("Location"))
	assert.Equal(t, http.StatusOK, b.Get("/auth/ui").Code)

	// The continuation is single-use.
	w = h.NewBrowser(t, env.Handler).Post("/auth/ui/login/2fa", url.Values{"temp_token": {tempToken}, "code": {next}})
	assert.Contains(t, w.Body.String(), "This sign-in has expired.")
}

// An expired access cookie is replaced from the refresh cookie, for both
// strategies, so an administrator is not sent back to sign in every
// fifteen minutes.
func TestUI_RefreshesExpiredCredentials(t *testing.T) {
	for name, session := range map[string]bool{"stateless": false, "session": true} {
		t.Run(name, func(t *testing.T) {
			env := h.SetupUI(t, h.UIOptions{Session: session})
			uiAdmin(t, env, "root@example.com")
			b := h.NewBrowser(t, env.Handler)
			require.Equal(t, http.StatusSeeOther, b.SignIn("root@example.com", uiPassword).Code)
			oldRefresh := b.Cookies["goauth_refresh_session"].Value

			delete(b.Cookies, "goauth_access_session") // the browser dropped it at expiry
			w := b.Get("/auth/ui")
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.NotEmpty(t, b.Cookies["goauth_access_session"], "a new access cookie is set")
			assert.NotEqual(t, oldRefresh, b.Cookies["goauth_refresh_session"].Value, "the refresh token rotated")

			// Signing out ends the grant: the refresh cookie no longer works.
			stale := b.Cookies["goauth_refresh_session"]
			require.Equal(t, http.StatusSeeOther, b.Post("/auth/ui/logout", url.Values{}).Code)
			replay := h.NewBrowser(t, env.Handler)
			replay.Cookies[stale.Name] = stale
			assert.Equal(t, http.StatusSeeOther, replay.Get("/auth/ui").Code, "a signed-out grant cannot be refreshed")
		})
	}
}

// The console's sign-in is rate limited like the JSON one, by address and
// by account, with form bodies read for the account.
func TestUI_SignInIsRateLimited(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{RateLimit: &config.RateLimitModuleConfig{}})
	uiAdmin(t, env, "root@example.com")
	b := h.NewBrowser(t, env.Handler)
	limited := false
	for range 12 {
		if b.SignIn("root@example.com", "wrong-password").Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	assert.True(t, limited, "repeated failures for one account are limited")
}

// Config.Path mounts the console at a path of its own, outside BasePath.
func TestUI_MountedAtItsOwnPath(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{UI: &ui.Config{Path: "/admin/"}, Audit: true})
	uiAdmin(t, env, "root@example.com")
	b := h.NewBrowser(t, env.Handler)

	assert.Equal(t, http.StatusNotFound, b.Get("/auth/ui/login").Code, "nothing is served under BasePath any more")

	w := b.Get("/admin/users")
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/login?next=%2Fadmin%2Fusers", w.Header().Get("Location"))

	page := b.Get("/admin/login").Body.String()
	assert.Contains(t, page, `action="/admin/login"`)
	assert.Contains(t, page, `href="/admin/assets/app.css?v=`)
	assert.Equal(t, http.StatusOK, b.Get("/admin/assets/htmx.min.js").Code)

	w = b.Post("/admin/login", url.Values{"email": {"root@example.com"}, "password": {uiPassword}, "next": {"/admin/users"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/admin/users", w.Header().Get("Location"))

	w = b.Get("/admin")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `href="/admin/users"`, "links follow the mount point")
	assert.Contains(t, w.Body.String(), `href="/admin/audit"`)
	assert.Equal(t, http.StatusOK, b.Get("/admin/audit").Code)

	// A next outside the console is still refused.
	b = h.NewBrowser(t, env.Handler)
	w = b.Post("/admin/login", url.Values{"email": {"root@example.com"}, "password": {uiPassword}, "next": {"/auth/me"}})
	assert.Equal(t, "/admin", w.Header().Get("Location"))

	// The JSON API is still under BasePath.
	assert.Equal(t, http.StatusUnauthorized, h.JSONGet(env.Handler, "/auth/me").Code)
}

func TestUI_PathMustBeReachableAndClean(t *testing.T) {
	start := func(path, cookiePath string) error {
		a, err := auth.New(&config.Config{
			Storage:  h.NewStore(t),
			BasePath: "/auth",
			Security: types.SecurityConfig{
				JwtSecretKey: strings.Repeat("k", 32), EncryptionKey: strings.Repeat("e", 32),
				Session: types.SessionConfig{Path: cookiePath},
			},
			RateLimit: &config.RateLimitModuleConfig{Disabled: true},
			Migration: config.MigrationConfig{Auto: true},
		})
		require.NoError(t, err)
		require.NoError(t, a.Use(ui.New(&ui.Config{Path: path})))
		err = a.Initialize(context.Background())
		if err == nil {
			require.NoError(t, a.Close())
		}
		return err
	}
	err := start("/admin", "/auth")
	require.Error(t, err, "credential cookies limited to /auth never reach /admin")
	assert.Contains(t, err.Error(), "would never receive the credential cookies")
	assert.NoError(t, start("/auth/console", "/auth"))
	assert.NoError(t, start("/admin", ""))

	for _, bad := range []string{"/", "admin", "/admin/../x", "/admin/{id}"} {
		assert.Error(t, start(bad, ""), bad)
	}
}
