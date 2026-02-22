package admin

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/bete7512/goauth/internal/modules/admin/handlers"
	"github.com/bete7512/goauth/internal/modules/admin/middlewares"
	"github.com/bete7512/goauth/internal/modules/admin/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/openapi.yml
var openapiSpec []byte

type AdminModule struct {
	deps       config.ModuleDependencies
	handlers   *handlers.AdminHandler
	config     *Config
	middleware *middlewares.AdminAuthMiddleware
}

type Config struct {
	// Optional custom repositories for testing
	AuditLogRepository models.AuditLogRepository
	UserRepository     models.UserRepository
}

var _ config.Module = (*AdminModule)(nil)

func New(cfg *Config) *AdminModule {
	if cfg == nil {
		cfg = &Config{}
	}
	return &AdminModule{
		config: cfg,
	}
}

func (m *AdminModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Get User repository from core module
	var userRepo models.UserRepository
	if m.config.UserRepository != nil {
		userRepo = m.config.UserRepository
	} else {
		// Get from core storage
		if deps.Storage != nil {
			coreStorage := deps.Storage.Core()
			if coreStorage != nil {
				userRepo = coreStorage.Users()
			}
		}
		if userRepo == nil {
			return fmt.Errorf("admin module: user repository not available")
		}
	}

	// Initialize middleware
	m.middleware = middlewares.NewAdminAuthMiddleware(deps)

	// Initialize services with both repositories
	adminService := services.NewAdminService(deps, userRepo)

	// Initialize handlers
	m.handlers = handlers.NewAdminHandler(deps, adminService)

	return nil
}

func (m *AdminModule) Name() string {
	return string(types.AdminModule)
}

func (m *AdminModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *AdminModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{
		{
			Name:       (types.MiddlewareAdminAuth),
			Middleware: m.middleware.Middleware,
			Priority:   40,
			ApplyTo:    []types.RouteName{},
			Global:     false,
		},
	}
}

func (m *AdminModule) Models() []any {
	return []any{}
}

func (m *AdminModule) RegisterHooks(events types.EventBus) error {
	// register subscriptions here
	events.Subscribe(types.EventAdminAction, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		// Handle admin action logging asynchronously
		return nil
	}))
	return nil
}

func (m *AdminModule) Dependencies() []string {
	// Admin module depends on core module for authentication
	return []string{string(types.CoreModule)}
}

func (m *AdminModule) OpenAPISpecs() []byte {
	return openapiSpec
}
