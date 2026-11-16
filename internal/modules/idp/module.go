// Package idp implements the identity provider module: GoAuth as an OpenID
// Connect provider. Other applications sign users in with the host's
// accounts through the authorization code flow and receive an ID token that
// says who the user is.
package idp

import (
	"context"
	"embed"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/idp/handlers"
	"github.com/bete7512/goauth/internal/modules/idp/services"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

//go:embed docs/openapi.yml
var openapiSpec []byte

//go:embed migrations
var migrationFS embed.FS

const defaultCleanupInterval = time.Hour

// IDPModule provides the OpenID Connect provider.
type IDPModule struct {
	deps     config.ModuleDependencies
	config   *config.IDPModuleConfig
	service  services.IDPService
	handlers *handlers.IDPHandler
}

// Compile-time check that IDPModule implements config.Module
var _ config.Module = (*IDPModule)(nil)

// New creates an IDPModule. The configuration is copied, so later changes to
// cfg have no effect.
func New(cfg *config.IDPModuleConfig) *IDPModule {
	snapshot := config.IDPModuleConfig{}
	if cfg != nil {
		snapshot = *cfg
	}
	snapshot.SigningKey.PrivateKeyPEM = append([]byte(nil), snapshot.SigningKey.PrivateKeyPEM...)
	snapshot.SigningKey.RetiredKeys = append([]types.JWTVerificationKey(nil), snapshot.SigningKey.RetiredKeys...)
	snapshot.Clients = append([]config.IDPClientConfig(nil), snapshot.Clients...)
	for i := range snapshot.Clients {
		client := &snapshot.Clients[i]
		client.RedirectURIs = append([]string(nil), client.RedirectURIs...)
		client.Scopes = append([]string(nil), client.Scopes...)
	}
	return &IDPModule{config: &snapshot}
}

// Name returns the module identifier
func (m *IDPModule) Name() string {
	return string(types.IDPModule)
}

// Init validates the configuration, writes the clients declared in it, and
// wires the service and handlers.
func (m *IDPModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps
	settings, err := services.ResolveSettings(deps, m.config)
	if err != nil {
		return err
	}
	if deps.Storage == nil || deps.Storage.Core() == nil {
		return errors.New("idp: core storage is required")
	}
	store := deps.Storage.IDP()
	if store == nil {
		return errors.New("idp: the storage backend has no identity provider stores (Storage.IDP returned nil)")
	}
	service := services.NewIDPService(deps, settings, services.Stores{
		Clients: store.Clients(),
		Grants:  store.Grants(),
		Users:   deps.Storage.Core().Users(),
		Tokens:  deps.Storage.Core().Tokens(),
	})
	if err := service.Seed(ctx); err != nil {
		return err
	}
	m.service = service
	m.handlers = handlers.NewIDPHandler(service, deps, settings)

	interval := m.config.CleanupInterval
	if interval == 0 {
		interval = defaultCleanupInterval
	}
	if interval > 0 {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					service.Cleanup(context.Background())
				}
			}
		}()
	}

	deps.Logger.Info("idp: module initialized",
		"issuer", settings.Issuer,
		"signing_key_id", settings.Signer.KeyID(),
		"clients", len(m.config.Clients),
		"admin_api", settings.AdminAPI,
	)
	if len(m.config.Clients) == 0 && !settings.AdminAPI {
		deps.Logger.Warn("idp: no client application can sign users in: declare one in IDPModuleConfig.Clients or enable AdminAPI")
	}
	return nil
}

// RevokeUserGrants disconnects every client application of a user and
// returns how many were disconnected. It fails before initialization.
func (m *IDPModule) RevokeUserGrants(ctx context.Context, userID string) (int64, *types.GoAuthError) {
	if m.service == nil {
		return 0, types.NewInternalError("idp: the module is not initialized")
	}
	return m.service.RevokeUserGrants(ctx, userID)
}

// Routes returns HTTP routes for the identity provider module
func (m *IDPModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

// Middlewares returns middleware configurations for this module
func (m *IDPModule) Middlewares() []config.MiddlewareConfig {
	return nil
}

// RegisterHooks registers event handlers for this module. When an
// administrator deletes a user, the record of which applications that user
// approved goes with the account.
func (m *IDPModule) RegisterHooks(events types.EventBus) error {
	if events == nil {
		return nil
	}
	events.Subscribe(types.EventAdminUserDeleted, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		if m.service == nil {
			return nil
		}
		data, ok := types.EventDataAs[map[string]interface{}](event)
		if !ok {
			return nil
		}
		userID, _ := data["target_id"].(string)
		if userID == "" {
			return nil
		}
		if _, authErr := m.service.RevokeUserGrants(ctx, userID); authErr != nil {
			m.deps.Logger.Warnf("idp: failed to remove the grants of deleted user %s: %v", userID, authErr)
		}
		return nil
	}))
	return nil
}

// Dependencies returns required module names. The admin API needs the admin
// module's middleware.
func (m *IDPModule) Dependencies() []string {
	dependencies := []string{string(types.CoreModule)}
	if m.config.AdminAPI {
		dependencies = append(dependencies, string(types.AdminModule))
	}
	return dependencies
}

// OpenAPISpecs returns the module's OpenAPI specification
func (m *IDPModule) OpenAPISpecs() []byte {
	return openapiSpec
}

// Migrations returns the module's SQL migrations
func (m *IDPModule) Migrations() types.ModuleMigrations {
	return utils.ParseMigrations(migrationFS)
}

// ServiceOf returns the identity provider's service, or nil before Init. It
// is a function rather than a method so that it is reachable only from
// inside GoAuth, for the ui module's pages.
func ServiceOf(m *IDPModule) services.IDPService {
	if m == nil {
		return nil
	}
	return m.service
}
