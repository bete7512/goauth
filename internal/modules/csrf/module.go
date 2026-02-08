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

//go:embed docs/swagger.yml
var swaggerSpec []byte

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
	if cfg == nil {
		cfg = &config.CSRFModuleConfig{}
	}
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
	m.handler = csrf_handlers.NewCSRFHandler(m.service, m.config)
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
		},
	}
}

func (m *CSRFModule) Models() []interface{} {
	return nil
}

func (m *CSRFModule) RegisterHooks(_ types.EventBus) error {
	return nil
}

func (m *CSRFModule) Dependencies() []string {
	return nil
}

func (m *CSRFModule) SwaggerSpec() []byte {
	return swaggerSpec
}
