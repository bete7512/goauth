package magiclink

import (
	"context"
	"errors"

	_ "embed"

	"github.com/bete7512/goauth/internal/modules/magiclink/handlers"
	"github.com/bete7512/goauth/internal/modules/magiclink/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/swagger.yml
var swaggerSpec []byte

type MagicLinkModule struct {
	deps          config.ModuleDependencies
	handlers      *handlers.MagicLinkHandler
	config        *config.MagicLinkModuleConfig
	customStorage types.CoreStorage
}

var _ config.Module = (*MagicLinkModule)(nil)

// New creates a new MagicLinkModule.
// customStorage is optional — if nil, storage is obtained from deps.Storage.Core().
func New(cfg *config.MagicLinkModuleConfig, customStorage types.CoreStorage) *MagicLinkModule {
	if cfg == nil {
		cfg = &config.MagicLinkModuleConfig{}
	}
	return &MagicLinkModule{
		config:        cfg,
		customStorage: customStorage,
	}
}

func (m *MagicLinkModule) Name() string {
	return string(types.MagicLinkModule)
}

func (m *MagicLinkModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	var coreStorage types.CoreStorage
	if m.customStorage != nil {
		coreStorage = m.customStorage
	} else if deps.Storage != nil {
		coreStorage = deps.Storage.Core()
	}

	if coreStorage == nil {
		return errors.New("core storage is required for magic link module")
	}

	var securityManager *security.SecurityManager
	if deps.SecurityManager != nil {
		securityManager = deps.SecurityManager
	} else {
		securityManager = security.NewSecurityManager(deps.Config.Security)
	}

	service := services.NewMagicLinkService(
		deps,
		coreStorage.Users(),
		coreStorage.Tokens(),
		securityManager,
		m.config,
	)

	m.handlers = handlers.NewMagicLinkHandler(service, deps, m.config)

	return nil
}

func (m *MagicLinkModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *MagicLinkModule) Middlewares() []config.MiddlewareConfig {
	return nil
}

func (m *MagicLinkModule) Models() []interface{} {
	// Reuses Token and User models from core module
	return nil
}

func (m *MagicLinkModule) RegisterHooks(events types.EventBus) error {
	return nil
}

func (m *MagicLinkModule) Dependencies() []string {
	return []string{string(types.CoreModule)}
}

func (m *MagicLinkModule) SwaggerSpec() []byte {
	return swaggerSpec
}
