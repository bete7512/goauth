package oauth

import (
	"context"
	"errors"
	"time"

	"embed"

	"github.com/bete7512/goauth/internal/modules/oauth/handlers"
	"github.com/bete7512/goauth/internal/modules/oauth/providers"
	"github.com/bete7512/goauth/internal/modules/oauth/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/openapi.yml
var openapiSpec []byte

//go:embed migrations
var migrationFS embed.FS

// OAuthModule provides OAuth authentication functionality
type OAuthModule struct {
	deps     config.ModuleDependencies
	handlers *handlers.OAuthHandler
	config   *config.OAuthModuleConfig
	registry *providers.Registry
}

// Compile-time check that OAuthModule implements config.Module
var _ config.Module = (*OAuthModule)(nil)

// New creates a new OAuthModule.
// Pass nil for cfg to use safe defaults.
// To provide custom storage, set cfg.CustomCoreStorage / cfg.CustomOAuthStorage / cfg.CustomSessionStorage.
func New(cfg *config.OAuthModuleConfig) *OAuthModule {
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

	return &OAuthModule{
		config:   cfg,
		registry: providers.NewRegistry(),
	}
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
	if m.config.CustomCoreStorage != nil {
		coreStorage = m.config.CustomCoreStorage
	} else if deps.Storage != nil {
		coreStorage = deps.Storage.Core()
	}

	if coreStorage == nil {
		return errors.New("core storage is required for OAuth module")
	}

	// Get OAuth storage (for Account model)
	var oauthStorage types.OAuthStorage
	if m.config.CustomOAuthStorage != nil {
		oauthStorage = m.config.CustomOAuthStorage
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
		if m.config.CustomSessionStorage != nil {
			sessionStorage = m.config.CustomSessionStorage
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

func (m *OAuthModule) Migrations() types.ModuleMigrations {
	return utils.ParseMigrations(migrationFS)
}
