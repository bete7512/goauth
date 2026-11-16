//go:build integration

package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUI_SignInWithEmailedCode(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{MagicLink: &config.MagicLinkModuleConfig{DeliveryMode: types.MagicLinkDeliveryModeCode}})
	events := h.RecordEvents(env.Auth, types.EventSendMagicLink)
	uiAdmin(t, env, "root@example.com")
	h.SignupUser(t, env.Handler, "plain@example.com")

	b := h.NewBrowser(t, env.Handler)
	page := b.Get("/auth/ui/login").Body.String()
	assert.Contains(t, page, "Email me a code")

	w := b.Post("/auth/ui/login/code", url.Values{"email": {"root@example.com"}, "next": {"/auth/ui/users"}})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Check your email")
	code := h.Nth(t, events, 1, func(d *types.MagicLinkRequestData) bool { return d.User != nil && d.User.Email == "root@example.com" }).Code
	require.NotEmpty(t, code)

	w = b.Post("/auth/ui/login/code/verify", url.Values{"email": {"root@example.com"}, "code": {"000000"}, "next": {"/auth/ui/users"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	if code == "000000" {
		t.Skip("the random code happened to be the wrong guess")
	}
	w = b.Post("/auth/ui/login/code/verify", url.Values{"email": {"root@example.com"}, "code": {code}, "next": {"/auth/ui/users"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui/users", w.Header().Get("Location"))
	assert.Equal(t, http.StatusOK, b.Get("/auth/ui/users").Code)

	// A plain user who signs in by code is turned away and holds nothing.
	plain := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusOK, plain.Post("/auth/ui/login/code", url.Values{"email": {"plain@example.com"}}).Code)
	code = h.Nth(t, events, 1, func(d *types.MagicLinkRequestData) bool { return d.User != nil && d.User.Email == "plain@example.com" }).Code
	w = plain.Post("/auth/ui/login/code/verify", url.Values{"email": {"plain@example.com"}, "code": {code}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "This console is for administrators.")
	assert.Empty(t, plain.Cookies)

	// An unknown address gets the same answer as a known one.
	w = h.NewBrowser(t, env.Handler).Post("/auth/ui/login/code", url.Values{"email": {"nobody@example.com"}})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Check your email")
}

func TestUI_LinkOnlyMagicLinksAreNotOffered(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{MagicLink: &config.MagicLinkModuleConfig{DeliveryMode: types.MagicLinkDeliveryModeLink}})
	assert.NotContains(t, h.NewBrowser(t, env.Handler).Get("/auth/ui/login").Body.String(), "Email me a code")
}

func TestUI_SignInWithOAuth(t *testing.T) {
	fake := h.NewFakeOAuthServer(t)
	cleanup := h.InstallFakeTransport(fake.Server.URL)
	defer cleanup()
	env := h.SetupUI(t, h.UIOptions{OAuthConfig: &config.OAuthModuleConfig{
		AllowSignup: true, AllowAccountLinking: true, TrustEmailVerification: true,
		Providers: map[string]*config.OAuthProviderConfig{"google": {ClientID: "test-google-client-id", ClientSecret: "secret", Enabled: true}},
	}})
	h.CreateUser(t, env.Store, "oauthuser@example.com", uiPassword, true)

	b := h.NewBrowser(t, env.Handler)
	page := b.Get("/auth/ui/login?next=%2Fauth%2Fui%2Fusers").Body.String()
	require.Contains(t, page, "Continue with Google")
	start := "/auth/oauth/google?redirect_uri=" + url.QueryEscape("/auth/ui/login/done?next="+url.QueryEscape("/auth/ui/users"))
	assert.Contains(t, page, strings.ReplaceAll(start, "&", "&amp;"))

	// The provider round trip: start, then the provider calls back.
	w := b.Get(start)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	authorize, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	fake.Nonce = authorize.Query().Get("nonce")
	fake.ClientID = authorize.Query().Get("client_id")
	w = b.Get("/auth/oauth/google/callback?code=fake_auth_code&state=" + authorize.Query().Get("state"))
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	location := w.Header().Get("Location")
	assert.Equal(t, "/auth/ui/login/done?next=%2Fauth%2Fui%2Fusers", location, "a local path, with no tokens in the URL")
	assert.NotContains(t, location, "access_token")

	w = b.Get(location)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui/users", w.Header().Get("Location"))
	assert.Equal(t, http.StatusOK, b.Get("/auth/ui/users").Code)

	// A failed or unfinished sign-in comes back with an error, never tokens.
	w = h.NewBrowser(t, env.Handler).Get("/auth/ui/login/done?error=challenge_required")
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "two-factor authentication")
}

func TestUI_PasskeySignInEndpoints(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Passkeys: true})
	b := h.NewBrowser(t, env.Handler)
	assert.Contains(t, b.Get("/auth/ui/login").Body.String(), "Sign in with a passkey")

	w := b.Post("/auth/ui/login/passkey/begin", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := h.ParseJSON(t, w.Body)
	assert.NotEmpty(t, body["challenge_token"])
	assert.NotNil(t, body["public_key"])

	w = b.PostJSON("/auth/ui/login/passkey/finish", `{"challenge_token":"x","credential_response":{"id":"bad"}}`)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String())
	assert.Empty(t, b.Cookies)

	// From another site, refused before anything runs.
	evil := h.NewBrowser(t, env.Handler)
	evil.Site = "cross-site"
	assert.Equal(t, http.StatusForbidden, evil.Post("/auth/ui/login/passkey/begin", nil).Code)
}
