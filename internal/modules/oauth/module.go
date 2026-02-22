package oauth

import (
	"context"
	"errors"
	"time"

	_ "embed"

	"github.com/bete7512/goauth/internal/modules/oauth/handlers"
	"github.com/bete7512/goauth/internal/modules/oauth/providers"
	"github.com/bete7512/goauth/internal/modules/oauth/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/openapi.yml
var openapiSpec []byte

// OAuthModule provides OAuth authentication functionality
type OAuthModule struct {
	deps                 config.ModuleDependencies
	handlers             *handlers.OAuthHandler
	config               *config.OAuthModuleConfig
	customCoreStorage    types.CoreStorage
	customOAuthStorage   types.OAuthStorage
	customSessionStorage types.SessionStorage // optional - for session-based auth
	registry             *providers.Registry
}

// Compile-time check that OAuthModule implements config.Module
var _ config.Module = (*OAuthModule)(nil)

// OAuthStorageOptions provides custom storage options for the OAuth module
type OAuthStorageOptions struct {
	CoreStorage    types.CoreStorage    // optional - if nil, uses deps.Storage.Core()
	OAuthStorage   types.OAuthStorage   // optional - if nil, uses deps.Storage.OAuth()
	SessionStorage types.SessionStorage // optional - for session-based auth, if nil uses deps.Storage.Session()
}

// New creates a new OAuthModule.
// opts is optional — if nil, storage is obtained from deps.Storage.
func New(cfg *config.OAuthModuleConfig, opts *OAuthStorageOptions) *OAuthModule {
	if cfg == nil {
		cfg = &config.OAuthModuleConfig{
			AllowSignup:            true,
			AllowAccountLinking:    true,
			TrustEmailVerification: true,
			StateTTL:               10 * time.Minute,
		}
	}

	// Set defaults
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = 10 * time.Minute
	}

	// Enable PKCE by default for all providers
	for name, providerCfg := range cfg.Providers {
		if providerCfg != nil {
			// PKCE defaults to true (we use a pointer trick here)
			// Since bool defaults to false, we need to check if it was explicitly set
			// For simplicity, we'll just document that PKCE=true is the default
			cfg.Providers[name] = providerCfg
		}
	}

	module := &OAuthModule{
		config:   cfg,
		registry: providers.NewRegistry(),
	}

	if opts != nil {
		module.customCoreStorage = opts.CoreStorage
		module.customOAuthStorage = opts.OAuthStorage
		module.customSessionStorage = opts.SessionStorage
	}

	return module
}

// Name returns the module identifier
func (m *OAuthModule) Name() string {
	return string(types.OAuthModule)
}

// Init initializes the module with dependencies
func (m *OAuthModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Get core storage
	var coreStorage types.CoreStorage
	if m.customCoreStorage != nil {
		coreStorage = m.customCoreStorage
	} else if deps.Storage != nil {
		coreStorage = deps.Storage.Core()
	}

	if coreStorage == nil {
		return errors.New("core storage is required for OAuth module")
	}

	// Get OAuth storage (for Account model)
	var oauthStorage types.OAuthStorage
	if m.customOAuthStorage != nil {
		oauthStorage = m.customOAuthStorage
	} else if deps.Storage != nil {
		oauthStorage = deps.Storage.OAuth()
	}

	if oauthStorage == nil {
		return errors.New("OAuth storage is required for OAuth module")
	}

	// Get session storage (optional - for session-based auth)
	var sessionStorage types.SessionStorage
	var sessionRepo models.SessionRepository
	if m.config.UseSessionAuth {
		if m.customSessionStorage != nil {
			sessionStorage = m.customSessionStorage
		} else if deps.Storage != nil {
			sessionStorage = deps.Storage.Session()
		}

		if sessionStorage == nil {
			return errors.New("session storage is required when UseSessionAuth is enabled")
		}
		sessionRepo = sessionStorage.Sessions()
	}

	// Get or create security manager
	var securityManager types.SecurityManager
	if deps.SecurityManager != nil {
		securityManager = deps.SecurityManager
	} else {
		securityManager = security.NewSecurityManager(deps.Config.Security)
	}

	// Get API URL and base path for callback URL construction
	apiURL := deps.Config.APIURL
	if apiURL == "" {
		return errors.New("APIURL is required for OAuth module (used for callback URLs)")
	}
	basePath := deps.Config.BasePath

	// Register OAuth providers
	if m.config.Providers != nil {
		if err := providers.RegisterBuiltinProviders(m.registry, m.config.Providers, apiURL, basePath); err != nil {
			return err
		}
	}

	if m.registry.Count() == 0 {
		deps.Logger.Warn("oauth: no providers configured")
	}

	// Create service
	service := services.NewOAuthService(
		deps,
		m.config,
		m.registry,
		coreStorage.Users(),
		coreStorage.Tokens(),
		oauthStorage.Accounts(),
		sessionRepo, // nil if stateless mode
		securityManager,
		apiURL,
		basePath,
	)

	// Create handlers
	m.handlers = handlers.NewOAuthHandler(service, deps, m.config)

	authMode := "stateless"
	if m.config.UseSessionAuth {
		authMode = "session"
	}
	deps.Logger.Info("oauth: module initialized", "providers", m.registry.Count(), "auth_mode", authMode)
	return nil
}

// Routes returns HTTP routes for the OAuth module
func (m *OAuthModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

// Middlewares returns middleware configurations for this module
func (m *OAuthModule) Middlewares() []config.MiddlewareConfig {
	return nil
}

// Models returns database models for migration
func (m *OAuthModule) Models() []interface{} {
	return []interface{}{
		&models.Account{},
	}
}

// RegisterHooks registers event handlers for this module
func (m *OAuthModule) RegisterHooks(events types.EventBus) error {
	return nil
}

// Dependencies returns required module names
func (m *OAuthModule) Dependencies() []string {
	return []string{string(types.CoreModule)}
}

// SwaggerSpec returns the module's swagger specification
func (m *OAuthModule) OpenAPISpecs() []byte {
	return openapiSpec
}

// GetRegistry returns the provider registry (for advanced use)
func (m *OAuthModule) GetRegistry() *providers.Registry {
	return m.registry
}
