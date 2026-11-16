//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"sort"
	"strings"
	"testing"

	internalui "github.com/bete7512/goauth/internal/modules/ui"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/admin"
	"github.com/bete7512/goauth/pkg/modules/audit"
	"github.com/bete7512/goauth/pkg/modules/idp"
	"github.com/bete7512/goauth/pkg/modules/invitation"
	"github.com/bete7512/goauth/pkg/modules/organization"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/modules/team"
	"github.com/bete7512/goauth/pkg/modules/twofactor"
	"github.com/bete7512/goauth/pkg/modules/ui"
	"github.com/bete7512/goauth/pkg/types"
	h "github.com/bete7512/goauth/tests/integration/testhelpers"
	"github.com/stretchr/testify/require"
)

// TestUI_EveryAdministrativeRouteHasAPageOrAReason enforces the rule that a
// feature an administrator can manage ships with its console page. It
// registers every module that has administrative routes, with every option
// that adds some, and checks each administrative route against
// internal/modules/ui/coverage.go.
//
// When this fails for a new route, add a page to the ui module and map the
// route in Covered, or, if the screen genuinely has to wait, add the route to
// Exempt with the reason.
func TestUI_EveryAdministrativeRouteHasAPageOrAReason(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	a, err := auth.New(&config.Config{
		Storage:   h.NewStore(t),
		APIURL:    "http://localhost:8080",
		BasePath:  "/auth",
		Security:  types.SecurityConfig{JwtSecretKey: strings.Repeat("k", 32), EncryptionKey: strings.Repeat("e", 32)},
		RateLimit: &config.RateLimitModuleConfig{Disabled: true},
		Migration: config.MigrationConfig{Auto: true},
	})
	require.NoError(t, err)
	for _, module := range []config.Component{
		ui.New(&ui.Config{UserPages: true}),
		admin.New(nil), audit.New(nil), invitation.New(nil), organization.New(nil), team.New(nil), twofactor.New(nil),
		rbac.New(&rbac.Config{Organizations: true, Teams: true}),
		idp.New(&config.IDPModuleConfig{
			SigningKey: config.IDPSigningKey{PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})},
			ConsentURL: "http://localhost:3000/consent",
			AdminAPI:   true,
		}),
	} {
		require.NoError(t, a.Use(module))
	}
	require.NoError(t, a.Initialize(context.Background()))
	t.Cleanup(func() { require.NoError(t, a.Close()) })

	// Module routes carry their middleware; Auth.Routes() does not.
	registered := map[types.RouteName]bool{}
	var routes []config.RouteInfo
	for _, route := range a.Routes() {
		registered[types.RouteName(route.Name)] = true
	}
	for _, name := range []string{"core", "admin", "audit", "invitation", "organization", "team", "twofactor", "rbac", "idp", "ui", "stateless"} {
		module, err := a.GetModule(name)
		require.NoError(t, err, name)
		routes = append(routes, module.Routes()...)
	}

	var missing []string
	for _, route := range routes {
		if !internalui.IsAdministrative(route) {
			continue
		}
		name := types.RouteName(route.Name)
		_, covered := internalui.Covered[name]
		_, exempt := internalui.Exempt[name]
		switch {
		case covered && exempt:
			t.Errorf("%s is both covered and exempt; remove one", name)
		case !covered && !exempt:
			missing = append(missing, route.Name)
		}
	}
	sort.Strings(missing)
	require.Empty(t, missing, "administrative routes with no console page and no stated reason; see internal/modules/ui/coverage.go")

	for name, page := range internalui.Covered {
		require.True(t, registered[name], "coverage.go names %s, which no module registers", name)
		require.True(t, registered[page], "%s is mapped to console page %s, which does not exist", name, page)
	}
	for name, reason := range internalui.Exempt {
		require.True(t, registered[name], "coverage.go exempts %s, which no module registers", name)
		require.NotEmpty(t, strings.TrimSpace(reason), "the exemption for %s needs a reason", name)
	}
}
