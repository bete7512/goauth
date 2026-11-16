package csrf

import (
	"context"

	_ "embed"

	csrf_handlers "github.com/bete7512/goauth/internal/modules/csrf/handlers"
	"github.com/bete7512/goauth/internal/modules/csrf/middlewares"
	"github.com/bete7512/goauth/internal/modules/csrf/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/openapi.yml
var openapiSpec []byte

// CSRFModule provides CSRF protection using the HMAC-based double-submit cookie pattern.
// Tokens are stateless — no server-side storage is required.
type CSRFModule struct {
	deps    config.ModuleDependencies
	service services.CSRFService
	handler *csrf_handlers.CSRFHandler
	config  *config.CSRFModuleConfig
}

var _ config.Module = (*CSRFModule)(nil)

// New creates a new CSRF module with the given configuration.
// If cfg is nil, defaults are used.
func New(cfg *config.CSRFModuleConfig) *CSRFModule {
	if cfg != nil {
		snapshot := *cfg
		cfg = &snapshot
	}
	if cfg == nil {
		cfg = &config.CSRFModuleConfig{}
	}
	cfg.ExcludePaths = append([]string(nil), cfg.ExcludePaths...)
	cfg.ProtectedMethods = append([]string(nil), cfg.ProtectedMethods...)
	return &CSRFModule{
		config: cfg,
	}
}

func (m *CSRFModule) Name() string {
	return "csrf"
}

func (m *CSRFModule) Init(_ context.Context, deps config.ModuleDependencies) error {
	m.deps = deps
	m.service = services.NewCSRFService(deps.Config.Security.JwtSecretKey, m.config)
	m.handler = csrf_handlers.NewCSRFHandler(m.service, m.config, deps.Config != nil && deps.Config.Security.Session.AllowInsecureCookies)
	return nil
}

func (m *CSRFModule) Routes() []config.RouteInfo {
	return m.handler.GetRoutes()
}

func (m *CSRFModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{
		{
			Name:       "csrf.protect",
			Middleware: middlewares.NewCSRFMiddleware(m.service, m.config),
			Priority:   85,
			Global:     true,
			// These endpoints are called by other servers, not by a page
			// in the user's browser, and carry their own proof in the
			// request (client credentials, a signed assertion, a one-time
			// code, a bearer token). They never act on the browser's
			// cookies, so there is nothing for a cross-site request to
			// forge, and their callers cannot hold a CSRF token.
			ExcludeFrom: []types.RouteName{
				types.RouteSAMLACS,
				types.RouteIDPToken,
				types.RouteIDPUserInfoPost,
				// The ui module's pages are same-origin HTML forms. Every
				// ui route is wrapped in net/http's CrossOriginProtection,
				// which refuses cross-site requests by Sec-Fetch-Site and
				// Origin, so they need no token of this module's.
				"ui.*",
			},
		},
	}
}

func (m *CSRFModule) RegisterHooks(_ types.EventBus) error {
	return nil
}

func (m *CSRFModule) Dependencies() []string {
	return nil
}

func (m *CSRFModule) OpenAPISpecs() []byte {
	return openapiSpec
}

func (m *CSRFModule) Migrations() types.ModuleMigrations {
	return types.ModuleMigrations{}
}
