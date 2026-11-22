// Package platform sets GoAuth up for the tracker: accounts, organizations,
// nested teams, roles and the admin console.
package platform

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/pkg/adapters/stdhttp"
	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/modules/admin"
	"github.com/bete7512/goauth/pkg/modules/audit"
	"github.com/bete7512/goauth/pkg/modules/organization"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/modules/team"
	"github.com/bete7512/goauth/pkg/modules/ui"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage"
)

// Settings are what the platform needs from the environment.
type Settings struct {
	Origin        string // e.g. http://localhost:8080
	JWTSecret     string
	EncryptionKey string
	// DSN of a SQLite database; the default keeps everything in memory.
	DSN string
	// ConsolePath is where the admin console is served, such as "/admin".
	ConsolePath string
}

// Platform is GoAuth, set up.
type Platform struct {
	Auth  *auth.Auth
	Authz *rbac.Module
	Store types.Storage
	// ConsolePath is where the admin console is served.
	ConsolePath string
}

// New registers the modules and initializes GoAuth.
func New(ctx context.Context, s Settings) (*Platform, error) {
	if s.ConsolePath == "" {
		s.ConsolePath = "/ui"
	}
	if s.DSN == "" {
		s.DSN = "file:goauth-rbac-example?mode=memory&cache=shared"
	}
	// One connection: with a shared-cache SQLite database, a second connection
	// writing at the same time (an event handler during a sign-in) fails with
	// "database table is locked" instead of waiting.
	store, err := storage.NewGormStorage(storage.GormConfig{Dialect: types.DialectTypeSqlite, DSN: s.DSN, LogLevel: "silent", MaxOpenConns: 1, MaxIdleConns: 1})
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	a, err := auth.New(&config.Config{
		Storage:   store,
		APIURL:    s.Origin,
		BasePath:  "/auth",
		Core:      &config.CoreConfig{},
		Migration: config.MigrationConfig{Auto: true},
		Security: types.SecurityConfig{
			JwtSecretKey:  s.JWTSecret,
			EncryptionKey: s.EncryptionKey,
			// The API takes bearer tokens; the admin console uses cookies.
			AuthMode: types.AuthModeBoth,
			// Plain http on localhost. Never set this in production.
			Session: types.SessionConfig{AllowInsecureCookies: true},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	authz := rbac.New(&rbac.Config{
		// Roles can be held inside organizations and inside teams.
		Organizations: true,
		Teams:         true,
		Roles:         Roles,
		// Every refusal is logged with its reason; a real application
		// might count them or send them to its audit trail.
		OnDeny: func(w http.ResponseWriter, r *http.Request, c rbac.Check) {
			http.Error(w, fmt.Sprintf(`{"error":"forbidden","permission":%q}`, c.Permission), http.StatusForbidden)
		},
	})

	for _, module := range []config.Component{
		organization.New(nil),
		team.New(nil),
		authz,
		// Audit records who did what; its admin routes need the admin module.
		admin.New(nil),
		audit.New(nil),
		// The admin console, for super admins, at Settings.ConsolePath.
		ui.New(&ui.Config{Path: s.ConsolePath, Title: "Acme Tracker"}),
	} {
		if err := a.Use(module); err != nil {
			return nil, fmt.Errorf("register module: %w", err)
		}
	}
	if err := a.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	authz.Define(PermReportExport, "Export platform-wide reports")
	authz.Define(PermInvoiceApprove, "Approve an invoice for payment")
	authz.Define(PermProjectArchive, "Archive a project")
	return &Platform{Auth: a, Authz: authz, Store: store, ConsolePath: s.ConsolePath}, nil
}

// Mount serves GoAuth's own routes (/auth/... and the console) on mux and
// returns the handler to serve.
func (p *Platform) Mount(mux *http.ServeMux) http.Handler {
	return stdhttp.Register(mux, p.Auth)
}

// Close releases GoAuth's resources.
func (p *Platform) Close() error { return p.Auth.Close() }

// TeamOrg returns the organization a team belongs to, for code that needs
// to file a new resource under the right organization.
func (p *Platform) TeamOrg(ctx context.Context, teamID string) (string, error) {
	t, err := p.Store.Team().Teams().FindByID(ctx, teamID)
	if err != nil {
		return "", err
	}
	return t.OrgID, nil
}
