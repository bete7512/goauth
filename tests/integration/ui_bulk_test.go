//go:build integration

package integration_test

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"strings"
	"testing"

	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUI_BulkUserActions(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{})
	rootID := uiAdmin(t, env, "root@example.com")
	alice, _ := h.SignupUser(t, env.Handler, "alice@example.com")
	bob, _ := h.SignupUser(t, env.Handler, "bob@example.com")
	b := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, b.SignIn("root@example.com", uiPassword).Code)

	page := b.Get("/auth/ui/users").Body.String()
	assert.Contains(t, page, `name="ids" value="`+alice+`"`)
	assert.NotContains(t, page, `name="ids" value="`+rootID+`"`, "the administrator cannot select themselves")

	users := env.Store.Core().Users()
	w := b.Post("/auth/ui/users/bulk", url.Values{"action": {"deactivate"}, "ids": {alice, bob, alice}})
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/auth/ui/users?notice=bulk-done&n=2&skipped=0", w.Header().Get("Location"))
	assert.Contains(t, b.Get(w.Header().Get("Location")).Body.String(), "Done for 2 user(s).")
	for _, id := range []string{alice, bob} {
		user, err := users.FindByID(context.Background(), id)
		require.NoError(t, err)
		assert.False(t, user.Active)
	}

	// The administrator's own account is skipped even when posted.
	w = b.Post("/auth/ui/users/bulk", url.Values{"action": {"activate"}, "ids": {alice, rootID}, "q": {"example"}})
	assert.Equal(t, "/auth/ui/users?q=example&notice=bulk-partial&n=1&skipped=1", w.Header().Get("Location"))
	user, err := users.FindByID(context.Background(), alice)
	require.NoError(t, err)
	assert.True(t, user.Active)

	w = b.Post("/auth/ui/users/bulk", url.Values{"action": {"delete"}, "ids": {bob}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	_, err = users.FindByID(context.Background(), bob)
	assert.Error(t, err, "deleted")

	assert.Equal(t, http.StatusBadRequest, b.Post("/auth/ui/users/bulk", url.Values{"action": {"promote"}, "ids": {alice}}).Code)
	assert.Equal(t, "/auth/ui/users?notice=bulk-none", b.Post("/auth/ui/users/bulk", url.Values{"action": {"delete"}}).Header().Get("Location"))
	// Counts in the notice are only ever numbers.
	assert.NotContains(t, b.Get("/auth/ui/users?notice=bulk-done&n=<b>x</b>").Body.String(), "<b>x</b>")
}

func TestUI_CSVExports(t *testing.T) {
	env := h.SetupUI(t, h.UIOptions{Audit: true, Organizations: true})
	uiAdmin(t, env, "root@example.com")
	h.SignupUser(t, env.Handler, "alice@example.com")
	evil := h.CreateUser(t, env.Store, "evil@example.com", uiPassword, false)
	user, err := env.Store.Core().Users().FindByID(context.Background(), evil)
	require.NoError(t, err)
	user.Name = "=HYPERLINK(\"http://x\")"
	require.NoError(t, env.Store.Core().Users().Update(context.Background(), user))

	b := h.NewBrowser(t, env.Handler)
	require.Equal(t, http.StatusSeeOther, b.SignIn("root@example.com", uiPassword).Code)

	w := b.Get("/auth/ui/users/export.csv")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "text/csv; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), `attachment; filename="users-`)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 4, "header and three users")
	assert.Equal(t, "email", rows[0][1])
	var names []string
	for _, row := range rows[1:] {
		names = append(names, row[3])
	}
	assert.Contains(t, names, "'=HYPERLINK(\"http://x\")", "a formula is neutralised")

	w = b.Get("/auth/ui/users/export.csv?q=alice")
	rows, err = csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 2, "the export follows the search")

	w = b.Get("/auth/ui/orgs/export.csv")
	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.HasPrefix(w.Body.String(), "id,name,slug,owner_id,active,created_at"))

	w = b.Get("/auth/ui/audit/export.csv")
	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.HasPrefix(w.Body.String(), "id,created_at,action,"))

	plain := h.NewBrowser(t, env.Handler)
	assert.NotEqual(t, http.StatusOK, plain.Get("/auth/ui/users/export.csv").Code, "exports need a signed-in administrator")
}
