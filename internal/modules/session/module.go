package session

import (
	"context"
	"errors"

	_ "embed"

	"github.com/bete7512/goauth/internal/modules/session/handlers"
	"github.com/bete7512/goauth/internal/modules/session/models"
	"github.com/bete7512/goauth/internal/modules/session/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/swagger.yml
var swaggerSpec []byte

type SessionModule struct {
	deps          config.ModuleDependencies
	handlers      *handlers.SessionHandler
	config        *config.SessionModuleConfig
	customStorage types.SessionStorage
}

var _ config.Module = (*SessionModule)(nil)

// New creates a new SessionModule
// customStorage is optional - if nil, storage will be obtained from deps.Storage.Session()
func New(cfg *config.SessionModuleConfig, customStorage types.SessionStorage) *SessionModule {
	if cfg == nil {
		cfg = &config.SessionModuleConfig{}
	}
	return &SessionModule{
		config:        cfg,
		customStorage: customStorage,
	}
}

func (m *SessionModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Get session storage - use custom if provided, otherwise from main storage
	var sessionStorage types.SessionStorage
	if m.customStorage != nil {
		sessionStorage = m.customStorage
	} else if deps.Storage != nil {
		sessionStorage = deps.Storage.Session()
	}

	if sessionStorage == nil {
		return errors.New("session storage is required")
	}

	// Get core storage for user repository
	var coreStorage types.CoreStorage
	if deps.Storage != nil {
		coreStorage = deps.Storage.Core()
	}

	if coreStorage == nil {
		return errors.New("core storage is required for session module")
	}

	// Initialize security manager
	securityManager := security.NewSecurityManager(m.deps.Config.Security)
	m.deps.SecurityManager = securityManager

	// Initialize handlers with all dependencies
	// Repositories now use concrete types - no adapters needed
	m.handlers = handlers.NewSessionHandler(
		services.NewSessionService(
			m.deps,
			coreStorage.Users(),
			sessionStorage.Sessions(),
			m.deps.Logger,
			securityManager,
			m.config,
		),
		m.deps,
	)

	return nil
}

func (m *SessionModule) SwaggerSpec() []byte {
	return swaggerSpec
}

func (m *SessionModule) Name() string {
	return string(types.SessionModule)
}

func (m *SessionModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *SessionModule) Middlewares() []config.MiddlewareConfig {
	return nil
}

func (m *SessionModule) Models() []any {
	return []any{
		&models.Session{},
	}
}

func (m *SessionModule) RegisterHooks(events types.EventBus) error {
	return nil
}

func (m *SessionModule) Dependencies() []string {
	return []string{string(types.CoreModule)}
}

