package session

import (
	"context"
	"errors"
	"time"

	"embed"

	"github.com/bete7512/goauth/internal/modules/session/handlers"
	"github.com/bete7512/goauth/internal/modules/session/middlewares"
	"github.com/bete7512/goauth/internal/modules/session/services"
	"github.com/bete7512/goauth/internal/security"
	cookie_security "github.com/bete7512/goauth/internal/security/cookie"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/openapi.yml
var openapiSpec []byte

//go:embed migrations
var migrationFS embed.FS

type SessionModule struct {
	deps          config.ModuleDependencies
	handlers      *handlers.SessionHandler
	config        *config.SessionModuleConfig
	customStorage types.SessionStorage
	validator     *services.SessionValidator // nil when strategy is "database"
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

	// Create encoder and validator for cookie_cache strategy
	var encoder cookie_security.CookieEncoder
	if m.config.Strategy == types.SessionStrategyCookieCache {
		// Apply defaults
		if m.config.CookieCacheTTL <= 0 {
			m.config.CookieCacheTTL = 5 * time.Minute
		}
		if m.config.UpdateAge <= 0 {
			m.config.UpdateAge = 10 * time.Minute
		}

		encoder = cookie_security.NewEncoder(m.config.CookieEncoding, m.deps.Config.Security.EncryptionKey)
		m.validator = services.NewSessionValidator(
			encoder,
			sessionStorage.Sessions(),
			services.ValidatorConfig{
				CacheTTL:          m.config.CookieCacheTTL,
				SessionTTL:        m.deps.Config.Security.Session.SessionTTL,
				SensitivePaths:    m.config.SensitivePaths,
				SlidingExpiration: m.config.SlidingExpiration,
				UpdateAge:         m.config.UpdateAge,
			},
		)
	}

	// Pass SessionModuleConfig through deps.Options so handlers can access it
	handlerDeps := m.deps
	handlerDeps.Options = m.config

	// Initialize handlers with all dependencies
	m.handlers = handlers.NewSessionHandler(
		services.NewSessionService(
			m.deps,
			coreStorage.Users(),
			sessionStorage.Sessions(),
			m.deps.Logger,
			securityManager,
			m.config,
		),
		handlerDeps,
		encoder,
	)

	return nil
}

func (m *SessionModule) OpenAPISpecs() []byte {
	return openapiSpec
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
	if m.validator == nil {
		return nil
	}
	return []config.MiddlewareConfig{{
		Name: "session.validate",
		Middleware: middlewares.NewSessionValidateMiddleware(
			m.validator,
			m.deps.Config.Security.Session,
			m.deps.Logger,
		),
		Priority: 45, // Runs after auth middleware (50)
		Global:   true,
		ExcludeFrom: []types.RouteName{
			types.RouteLogin,
			types.RouteSignup,
			types.RouteRefreshToken,
		},
	}}
}

func (m *SessionModule) RegisterHooks(events types.EventBus) error {
	return nil
}

func (m *SessionModule) Dependencies() []string {
	return []string{string(types.CoreModule)}
}

func (m *SessionModule) Migrations() types.ModuleMigrations {
	result := types.ModuleMigrations{}
	for _, d := range []types.DialectType{types.DialectTypePostgres, types.DialectTypeMysql, types.DialectTypeSqlite} {
		up, _ := migrationFS.ReadFile("migrations/" + string(d) + "/up.sql")
		down, _ := migrationFS.ReadFile("migrations/" + string(d) + "/down.sql")
		if len(up) > 0 {
			result[d] = types.MigrationFiles{Up: up, Down: down}
		}
	}
	return result
}
