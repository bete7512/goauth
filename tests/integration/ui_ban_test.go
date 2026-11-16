//go:build integration

package integration_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/modules/ui"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUI_BanAndUnban(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{UI: &ui.Config{UserPages: true}, Session: true})
	rootID := uiAdmin(t, env, "root@example.com")
	aliceID, _ := h.SignupUser(t, env.Handler, "alice@example.com")

	alice := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, alice.SignIn("alice@example.com", uiPassword).Code)
	admin := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, admin.SignIn("root@example.com", uiPassword).Code)

	userURL := "/auth/ui/users/" + aliceID
	assert.Equal(t, http.StatusUnprocessableEntity, admin.Post(userURL+"/ban", url.Values{"reason": {""}, "duration": {"24h"}}).Code, "a reason is required")
	assert.Equal(t, http.StatusUnprocessableEntity, admin.Post(userURL+"/ban", url.Values{"reason": {"x"}, "duration": {"99y"}}).Code)
	assert.Equal(t, http.StatusUnprocessableEntity, admin.Post("/auth/ui/users/"+rootID+"/ban", url.Values{"reason": {"x"}, "duration": {""}}).Code, "no banning yourself")

	w := admin.Post(userURL+"/ban", url.Values{"reason": {"Spam in ticket 12"}, "duration": {"24h"}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	page := admin.Get(userURL).Body.String()
	assert.Contains(t, page, "Reason: Spam in ticket 12")
	assert.Contains(t, page, "Lift ban")
	assert.Contains(t, admin.Get("/auth/ui/users").Body.String(), "Banned")

	// The ban works at once: the open session is gone, and signing in is refused.
	assert.Equal(t, http.StatusSeeOther, alice.Get("/auth/ui/account").Code)
	fresh := h.NewBrowser(t, env.Handler)
	w = fresh.SignIn("alice@example.com", uiPassword)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "This account cannot sign in.")

	// A ban that has ended no longer counts.
	user, err := env.Store.Core().Users().FindByID(context.Background(), aliceID)
	require.NoError(t, err)
	past := time.Now().Add(-time.Minute)
	user.BannedUntil = &past
	require.NoError(t, env.Store.Core().Users().Update(context.Background(), user))
	assert.Equal(t, http.StatusSeeOther, h.NewBrowser(t, env.Handler).SignIn("alice@example.com", uiPassword).Code)

	// Ban until lifted, then lift it.
	require.Equal(t, http.StatusSeeOther, admin.Post(userURL+"/ban", url.Values{"reason": {"Chargeback"}, "duration": {""}}).Code)
	assert.Contains(t, admin.Get(userURL).Body.String(), "until lifted")
	assert.Equal(t, http.StatusUnprocessableEntity, h.NewBrowser(t, env.Handler).SignIn("alice@example.com", uiPassword).Code)
	require.Equal(t, http.StatusSeeOther, admin.Post(userURL+"/unban", nil).Code)
	user, err = env.Store.Core().Users().FindByID(context.Background(), aliceID)
	require.NoError(t, err)
	assert.Nil(t, user.BannedAt)
	assert.Empty(t, user.BanReason)
	assert.Equal(t, http.StatusSeeOther, h.NewBrowser(t, env.Handler).SignIn("alice@example.com", uiPassword).Code)
}
