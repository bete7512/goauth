package stateless

import (
	"context"
	"errors"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers"
	"github.com/bete7512/goauth/internal/modules/stateless/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type StatelessModule struct {
	deps          config.ModuleDependencies
	handlers      *handlers.StatelessHandler
	config        *config.StatelessModuleConfig
	customStorage types.CoreStorage // Stateless uses core storage for tokens
}

var _ config.Module = (*StatelessModule)(nil)

// New creates a new StatelessModule
// customStorage is optional - if nil, storage will be obtained from deps.Storage.Core()
// Stateless module uses CoreStorage because it only needs users and tokens
func New(cfg *config.StatelessModuleConfig, customStorage types.CoreStorage) *StatelessModule {
	if cfg == nil {
		cfg = &config.StatelessModuleConfig{
			RefreshTokenRotation: true,
		}
	}
	return &StatelessModule{
		config:        cfg,
		customStorage: customStorage,
	}
}

func (m *StatelessModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Get core storage - use custom if provided, otherwise from main storage
	var coreStorage types.CoreStorage
	if m.customStorage != nil {
		coreStorage = m.customStorage
	} else if deps.Storage != nil {
		coreStorage = deps.Storage.Core()
	}

	if coreStorage == nil {
		return errors.New("core storage is required for stateless module")
	}
	// Initialize security manager
	securityManager := security.NewSecurityManager(m.deps.Config.Security)
	m.deps.SecurityManager = securityManager

	// Initialize handlers with all dependencies
	m.handlers = handlers.NewStatelessHandler(
		services.NewStatelessService(
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

func (m *StatelessModule) OpenAPISpecs() []byte {
	return nil
}

func (m *StatelessModule) Name() string {
	return string(types.StatelessModule)
}

func (m *StatelessModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *StatelessModule) Middlewares() []config.MiddlewareConfig {
	return nil
}

func (m *StatelessModule) Models() []any {
	return nil
}

func (m *StatelessModule) RegisterHooks(events types.EventBus) error {
	return nil
}

func (m *StatelessModule) Dependencies() []string {
	return []string{string(types.CoreModule)}
}
