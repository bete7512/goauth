//go:build integration

package integration_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/bete7512/goauth/pkg/modules/ui"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var sessionRevokeLink = regexp.MustCompile(`/auth/ui/account/sessions/([0-9a-f-]+)/revoke`)

func TestUI_AccountProfileAndSessions(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{UI: &ui.Config{UserPages: true}, Session: true})
	h.SignupUser(t, env.Handler, "self@example.com")

	laptop := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, laptop.SignIn("self@example.com", uiPassword).Code)
	phone := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, phone.SignIn("self@example.com", uiPassword).Code)

	page := laptop.Get("/auth/ui/account")
	require.Equal(t, http.StatusOK, page.Code, page.Body.String())
	body := page.Body.String()
	assert.Contains(t, body, "This device")
	links := sessionRevokeLink.FindAllStringSubmatch(body, -1)
	// Signing up started a session too; every session but this one has an
	// End button.
	require.Len(t, links, 2)

	// Profile: an invalid phone number is refused, a valid edit is saved.
	w := laptop.Post("/auth/ui/account", url.Values{"name": {"Self Person"}, "phone_number": {"not a phone"}})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	w = laptop.Post("/auth/ui/account", url.Values{"name": {"Self Person"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui/account?notice=saved", w.Header().Get("Location"))
	assert.Contains(t, laptop.Get("/auth/ui/account").Body.String(), "Self Person")

	// The current session cannot be ended from the list; the other can.
	for _, link := range links {
		w = laptop.Post("/auth/ui/account/sessions/"+link[1]+"/revoke", nil)
		require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	}
	assert.Equal(t, http.StatusSeeOther, phone.Get("/auth/ui/account").Code, "the ended session is signed out")
	assert.Equal(t, http.StatusOK, laptop.Get("/auth/ui/account").Code)

	// A new phone number ends every sign-in, this one included.
	w = laptop.Post("/auth/ui/account", url.Values{"name": {"Self Person"}, "phone_number": {"+14155550100"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui/login?notice=phone-changed", w.Header().Get("Location"))
	assert.Equal(t, http.StatusSeeOther, laptop.Get("/auth/ui/account").Code)
}

func TestUI_AccountPasswordChange(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{UI: &ui.Config{UserPages: true}})
	h.SignupUser(t, env.Handler, "self@example.com")
	b := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, b.SignIn("self@example.com", uiPassword).Code)

	cases := []struct {
		name    string
		form    url.Values
		message string
	}{
		{"wrong current", url.Values{"current_password": {"Wrong1234"}, "new_password": {"Newpass1234"}, "confirm_password": {"Newpass1234"}}, "Your current password is incorrect."},
		{"mismatch", url.Values{"current_password": {uiPassword}, "new_password": {"Newpass1234"}, "confirm_password": {"Other1234"}}, "The new passwords do not match."},
		{"same", url.Values{"current_password": {uiPassword}, "new_password": {uiPassword}, "confirm_password": {uiPassword}}, "different from the current one"},
		{"policy", url.Values{"current_password": {uiPassword}, "new_password": {"abc"}, "confirm_password": {"abc"}}, "password must"},
	}
	for _, tc := range cases {
		w := b.Post("/auth/ui/account/password", tc.form)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code, tc.name)
		assert.Contains(t, w.Body.String(), tc.message, tc.name)
	}

	stale := map[string]*http.Cookie{}
	for name, cookie := range b.Cookies {
		stale[name] = cookie
	}
	w := b.Post("/auth/ui/account/password", url.Values{"current_password": {uiPassword}, "new_password": {"Newpass1234"}, "confirm_password": {"Newpass1234"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui/login?notice=password-changed", w.Header().Get("Location"))

	old := h.NewBrowser(t, env.Handler)
	old.Cookies = stale
	assert.Equal(t, http.StatusSeeOther, old.Get("/auth/ui/account").Code, "credentials from before the change no longer work")

	fresh := h.NewBrowser(t, env.Handler)
	assert.Equal(t, http.StatusUnprocessableEntity, fresh.SignIn("self@example.com", uiPassword).Code)
	assert.Equal(t, http.StatusSeeOther, fresh.SignIn("self@example.com", "Newpass1234").Code)
}

func TestUI_AccountWithoutUserPages(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{})
	uiAdmin(t, env, "root@example.com")
	admin := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, admin.SignIn("root@example.com", uiPassword).Code)
	w := admin.Get("/auth/ui/account")
	require.Equal(t, http.StatusOK, w.Code, "administrators always have an account page")
	assert.Contains(t, w.Body.String(), "Change password")

	// A plain user signed in to the application holds cookies that reach
	// the console; without UserPages the account page still refuses them.
	h.SignupUser(t, env.Handler, "plain@example.com")
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"email":"plain@example.com","password":"`+uiPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.Handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	plain := h.NewBrowser(t, env.Handler)
	for _, cookie := range rec.Result().Cookies() {
		plain.Cookies[cookie.Name] = cookie
	}
	require.NotEmpty(t, plain.Cookies)
	assert.Equal(t, http.StatusForbidden, plain.Get("/auth/ui/account").Code)
	assert.Equal(t, http.StatusForbidden, plain.Post("/auth/ui/account/password", url.Values{"current_password": {uiPassword}, "new_password": {"Newpass1234"}, "confirm_password": {"Newpass1234"}}).Code)
}
