package admin

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/admin/handlers"
	"github.com/bete7512/goauth/internal/modules/admin/middlewares"
	"github.com/bete7512/goauth/internal/modules/admin/models"
	"github.com/bete7512/goauth/internal/modules/admin/services"
	coreModels "github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/pkg/config"
)

type AdminModule struct {
	deps     config.ModuleDependencies
	handlers *handlers.AdminHandler
	config   *Config
}

type Config struct {
	AuditLogRepository models.AuditLogRepository
	// You can optionally inject custom implementations
	UserRepository coreModels.UserRepository
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
		// Get from storage
		var err error
		auditLogRepo, err = config.GetTypedRepository[models.AuditLogRepository](
			deps.Storage,
			string(config.AdminAuditLogRepository),
		)
		if err != nil {
			return err
		}
	}

	// Get User repository from core module (RECOMMENDED WAY)
	var userRepo coreModels.UserRepository
	if m.config.UserRepository != nil {
		userRepo = m.config.UserRepository
	} else {
		// Access core module's user repository
		var err error
		userRepo, err = config.GetTypedRepository[coreModels.UserRepository](
			deps.Storage,
			string(config.CoreUserRepository),
		)
		if err != nil {
			return err
		}
	}

	// Initialize services with both repositories
	adminService := services.NewAdminService(deps, auditLogRepo, userRepo)

	// Initialize handlers
	m.handlers = handlers.NewAdminHandler(deps, adminService)

	return nil
}

func (m *AdminModule) Name() string {
	return string(config.AdminModule)
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
			Name:       "admin.auth",
			Middleware: middlewares.AdminAuthMiddleware,
			Priority:   40,
			ApplyTo:    []string{"admin.*"},
			Global:     false,
		},
	}
}

func (m *AdminModule) Models() []interface{} {
	return []interface{}{
		&models.AuditLog{},
	}
}

func (m *AdminModule) RegisterHooks(events config.EventBus) error {
	// Log admin actions
	events.Subscribe("admin:action", func(ctx context.Context, event interface{}) error {
		// Handle admin action logging
		return nil
	})
	return nil
}

func (m *AdminModule) Dependencies() []string {
	// Admin module depends on core module
	return []string{string(config.CoreModule)}
}


func (m *AdminModule) SwaggerSpec() []byte {
	return nil
}