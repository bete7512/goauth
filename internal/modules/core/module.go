package core

import (
	"context"
	"errors"

	"embed"

	"github.com/bete7512/goauth/internal/modules/core/handlers"
	"github.com/bete7512/goauth/internal/modules/core/middlewares"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type CoreModule struct {
	deps     config.ModuleDependencies
	handlers *handlers.CoreHandler
	config   *config.CoreConfig
}

//go:embed docs/openapi.yml
var openapiSpec []byte

//go:embed migrations
var migrationFS embed.FS

var _ config.Module = (*CoreModule)(nil)

// New creates a new CoreModule.
// Pass nil for cfg to use safe defaults.
// To provide custom storage, set cfg.CustomStorage.
func New(cfg *config.CoreConfig) *CoreModule {
	if cfg == nil {
		cfg = &config.CoreConfig{}
	}
	return &CoreModule{
		config: cfg,
	}
}

func (m *CoreModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Get core storage - use custom if provided, otherwise from main storage
	var coreStorage types.CoreStorage
	if m.config.CustomStorage != nil {
		coreStorage = m.config.CustomStorage
	} else if deps.Storage != nil {
		coreStorage = deps.Storage.Core()
	}

	if coreStorage == nil {
		return errors.New("core storage is required")
	}

	// Update config from dependencies if provided
	m.updateConfigFromDeps()

	// Initialize security manager
	securityManager := security.NewSecurityManager(m.deps.Config.Security)
	m.deps.SecurityManager = securityManager

	// Initialize handlers with all dependencies
	// Repositories now use concrete types - no adapters needed
	m.handlers = handlers.NewCoreHandler(
		core_services.NewCoreService(
			m.deps,
			coreStorage.Users(),
			coreStorage.Tokens(),
			m.deps.Logger,
			securityManager,
			m.config,
		),
		m.deps,
	)

	return nil
}

func (m *CoreModule) OpenAPISpecs() []byte {
	return openapiSpec
}

func (m *CoreModule) Name() string {
	return string(types.CoreModule)
}

func (m *CoreModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *CoreModule) Middlewares() []config.MiddlewareConfig {
	authMiddleware := middlewares.NewAuthMiddleware(m.deps.Config, m.deps.SecurityManager)
	return []config.MiddlewareConfig{
		{
			Name:       (types.MiddlewareAuth),
			Middleware: authMiddleware.AuthMiddleware,
			Priority:   50,
			ApplyTo:    []types.RouteName{},
			Global:     false,
		},
	}
}

func (m *CoreModule) RegisterHooks(events types.EventBus) error {
	return nil
}

func (m *CoreModule) Dependencies() []string {
	return nil
}

func (m *CoreModule) Migrations() types.ModuleMigrations {
	return utils.ParseMigrations(migrationFS)
}

func (m *CoreModule) updateConfigFromDeps() {
	if m.deps.Config.Core != nil {
		m.config = &config.CoreConfig{
			RequireEmailVerification: m.deps.Config.Core.RequireEmailVerification,
			RequirePhoneVerification: m.deps.Config.Core.RequirePhoneVerification,
			RequireUserName:          m.deps.Config.Core.RequireUserName,
			RequirePhoneNumber:       m.deps.Config.Core.RequirePhoneNumber,
		}
	}
}
