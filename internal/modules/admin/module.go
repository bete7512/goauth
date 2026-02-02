package admin

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/internal/modules/admin/handlers"
	"github.com/bete7512/goauth/internal/modules/admin/middlewares"
	"github.com/bete7512/goauth/internal/modules/admin/models"
	"github.com/bete7512/goauth/internal/modules/admin/services"
	"github.com/bete7512/goauth/pkg/config"
	pkgmodels "github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type AdminModule struct {
	deps     config.ModuleDependencies
	handlers *handlers.AdminHandler
	config   *Config
}

type Config struct {
	AuditLogRepository models.AuditLogRepository
	// You can optionally inject custom implementations
	UserRepository pkgmodels.UserRepository
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

	// Get AuditLog repository (admin's own repository)
	var auditLogRepo models.AuditLogRepository
	if m.config.AuditLogRepository != nil {
		auditLogRepo = m.config.AuditLogRepository
	} else {
		// TODO: Admin module needs its own storage interface for AuditLog
		// For now, this will fail if not provided via config
		return fmt.Errorf("admin module: AuditLogRepository must be provided via config")
	}

	// Get User repository from core module
	var userRepo pkgmodels.UserRepository
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

	// Initialize services with both repositories
	adminService := services.NewAdminService(deps, auditLogRepo, userRepo)

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
			Name:       string(types.MiddlewareAdminAuth),
			Middleware: middlewares.AdminAuthMiddleware,
			Priority:   40,
			ApplyTo:    []types.RouteName{}, // Routes now declare which middlewares they need via RouteInfo.Middlewares
			Global:     false,
		},
	}
}

func (m *AdminModule) Models() []any {
	return []any{
		&models.AuditLog{},
	}
}

func (m *AdminModule) RegisterHooks(events types.EventBus) error {
	// Log admin actions
	events.Subscribe(types.EventAdminAction, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		// Handle admin action logging
		return nil
	}))
	return nil
}

func (m *AdminModule) Dependencies() []string {
	// Admin module depends on core module
	return []string{string(types.CoreModule)}
}

func (m *AdminModule) SwaggerSpec() []byte {
	return nil
}
