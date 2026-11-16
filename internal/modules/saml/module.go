// Package saml implements the SAML 2.0 service-provider module: SP-initiated
// and optional IdP-initiated Web Browser SSO against identity providers such
// as Keycloak, Okta or Entra ID.
package saml

import (
	"context"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/saml/handlers"
	"github.com/bete7512/goauth/internal/modules/saml/providers"
	"github.com/bete7512/goauth/internal/modules/saml/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"

	_ "embed"
)

//go:embed docs/openapi.yml
var openapiSpec []byte

// SAMLModule provides SAML 2.0 service-provider authentication.
type SAMLModule struct {
	service  services.SAMLService
	deps     config.ModuleDependencies
	handlers *handlers.SAMLHandler
	config   *config.SAMLModuleConfig
	registry *providers.Registry
	frozen   bool
}

// Compile-time check that SAMLModule implements config.Module.
var _ config.Module = (*SAMLModule)(nil)

// New creates a SAMLModule. Pass nil for cfg to use safe defaults; a module
// without providers initializes but serves no connections.
func New(cfg *config.SAMLModuleConfig) *SAMLModule {
	if cfg == nil {
		cfg = &config.SAMLModuleConfig{
			AllowSignup: true,
			TrustEmail:  true,
		}
	} else {
		snapshot := *cfg
		cfg = &snapshot
	}
	if cfg.Providers != nil {
		copied := make(map[string]*config.SAMLProviderConfig, len(cfg.Providers))
		for name, provider := range cfg.Providers {
			if provider != nil {
				dup := *provider
				copied[name] = &dup
			}
		}
		cfg.Providers = copied
	}
	if cfg.RequestTTL <= 0 {
		cfg.RequestTTL = 10 * time.Minute
	}
	return &SAMLModule{config: cfg, registry: providers.NewRegistry()}
}

// Name returns the module identifier.
func (m *SAMLModule) Name() string {
	return string(types.SAMLModule)
}

// Init loads IdP metadata for every connection and wires the service and handlers.
func (m *SAMLModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps
	m.frozen = true
	if m.config.CustomCoreStorage != nil || m.config.CustomAccountStorage != nil || m.config.CustomSessionStorage != nil {
		return errors.New("saml: custom stores require a single aggregate transactional Storage adapter")
	}
	if deps.Config == nil {
		return errors.New("saml: config is required")
	}

	var coreStorage types.CoreStorage
	var accountStorage types.OAuthStorage
	if deps.Storage != nil {
		coreStorage = deps.Storage.Core()
		accountStorage = deps.Storage.OAuth()
	}
	if coreStorage == nil {
		return errors.New("saml: core storage is required")
	}
	if accountStorage == nil {
		return errors.New("saml: account storage is required (provided by the oauth module's accounts table)")
	}

	var sessionRepo models.SessionRepository
	if m.config.UseSessionAuth {
		if deps.Storage == nil || deps.Storage.Session() == nil {
			return errors.New("saml: session storage is required when UseSessionAuth is enabled")
		}
		sessionRepo = deps.Storage.Session().Sessions()
	}

	securityManager := deps.SecurityManager
	if securityManager == nil {
		securityManager = security.NewSecurityManager(deps.Config.Security)
	}

	if deps.Config.APIURL == "" {
		return errors.New("saml: APIURL is required (used for the ACS and metadata URLs)")
	}
	key, cert, err := providers.LoadKeyPair(m.config.SPCertificate, m.config.SPPrivateKey)
	if err != nil {
		return err
	}
	opts := providers.SPOptions{
		APIURL:      deps.Config.APIURL,
		BasePath:    deps.Config.BasePath,
		Key:         key,
		Certificate: cert,
		HTTPClient:  m.config.MetadataHTTPClient,
	}
	for name, providerCfg := range m.config.Providers {
		if providerCfg == nil {
			continue
		}
		if m.registry.Has(name) {
			continue // installed through RegisterProvider before Init
		}
		if providerCfg.Disabled {
			deps.Logger.Info("saml: provider disabled", "provider", name)
			continue
		}
		provider, err := providers.NewServiceProvider(ctx, name, providerCfg, opts)
		if err != nil {
			return err
		}
		if err := m.registry.Register(provider); err != nil {
			return err
		}
	}
	if m.registry.Count() == 0 {
		deps.Logger.Warn("saml: no providers configured")
	}

	service := services.NewSAMLService(
		deps,
		m.config,
		m.registry,
		coreStorage.Users(),
		coreStorage.Tokens(),
		accountStorage.Accounts(),
		sessionRepo,
		securityManager,
	)
	m.handlers = handlers.NewSAMLHandler(service, deps, m.config)
	m.service = service

	authMode := "stateless"
	if m.config.UseSessionAuth {
		authMode = "session"
	}
	deps.Logger.Info("saml: module initialized", "providers", m.registry.Count(), "auth_mode", authMode, "sign_requests", key != nil)
	return nil
}

// Routes returns HTTP routes for the SAML module.
func (m *SAMLModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

// Middlewares returns middleware configurations for this module.
func (m *SAMLModule) Middlewares() []config.MiddlewareConfig {
	return nil
}

// RegisterHooks registers event handlers for this module.
func (m *SAMLModule) RegisterHooks(events types.EventBus) error {
	return nil
}

// Dependencies returns required module names. Linked SAML subjects live in the
// accounts table that the OAuth module owns and migrates.
func (m *SAMLModule) Dependencies() []string {
	return []string{string(types.CoreModule), string(types.OAuthModule)}
}

// OpenAPISpecs returns the module's OpenAPI specification.
func (m *SAMLModule) OpenAPISpecs() []byte {
	return openapiSpec
}

// Migrations returns no migrations: the module reuses the accounts and tokens tables.
func (m *SAMLModule) Migrations() types.ModuleMigrations {
	return types.ModuleMigrations{}
}

// RegisterProvider installs a trusted in-process connection before Init, for
// hosts that load IdP metadata themselves or need a custom protocol adapter.
func (m *SAMLModule) RegisterProvider(provider providers.ServiceProvider) error {
	if m.frozen {
		return errors.New("saml: connections are frozen after initialization")
	}
	return m.registry.Register(provider)
}

// ServiceOf returns the saml service, or nil before Init. It is a function
// rather than a method so that it is reachable only from inside GoAuth, for
// the ui module's sign-in page.
func ServiceOf(m *SAMLModule) services.SAMLService {
	if m == nil {
		return nil
	}
	return m.service
}
