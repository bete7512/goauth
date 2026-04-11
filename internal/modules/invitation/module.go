package invitation

import (
	"context"
	"embed"
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/invitation/handlers"
	"github.com/bete7512/goauth/internal/modules/invitation/services"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

var (
	//go:embed docs/openapi.yml
	openapiSpec []byte

	//go:embed migrations
	migrationFS embed.FS
)

var _ config.Module = (*InvitationModule)(nil)

type InvitationModule struct {
	deps              config.ModuleDependencies
	config            *Config
	invitationHandler *handlers.InvitationHandler
}

func New(cfg *Config) *InvitationModule {
	if cfg == nil {
		cfg = &Config{}
	}
	cfg.applyDefaults()
	return &InvitationModule{config: cfg}
}

func (m *InvitationModule) Name() string {
	return string(types.InvitationModule)
}

func (m *InvitationModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	invStorage := deps.Storage.Invitation()
	if invStorage == nil {
		return fmt.Errorf("invitation storage is not available")
	}

	invitationRepo := invStorage.Invitations()
	userRepo := deps.Storage.Core().Users()

	invitationService := services.NewInvitationService(
		deps, invitationRepo, userRepo,
		m.config.InvitationExpiry, m.config.CallbackURL,
		m.config.DefaultPurpose, m.config.AllowedPurposes, m.config.MaxPendingPerEmail,
	)

	m.invitationHandler = handlers.NewInvitationHandler(deps, invitationService)

	deps.Logger.Info("Invitation module initialized")
	return nil
}

func (m *InvitationModule) Routes() []config.RouteInfo {
	return []config.RouteInfo{
		{Name: string(types.RouteInvitationSend), Path: "/invitations", Method: http.MethodPost, Handler: m.invitationHandler.Send, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteInvitationList), Path: "/invitations", Method: http.MethodGet, Handler: m.invitationHandler.List, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteInvitationMy), Path: "/invitations/my", Method: http.MethodGet, Handler: m.invitationHandler.MyInvitations, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteInvitationAccept), Path: "/invitations/accept", Method: http.MethodPost, Handler: m.invitationHandler.Accept, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteInvitationDecline), Path: "/invitations/decline", Method: http.MethodPost, Handler: m.invitationHandler.Decline, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteInvitationCancel), Path: "/invitations/{invId}", Method: http.MethodDelete, Handler: m.invitationHandler.Cancel, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
	}
}

func (m *InvitationModule) Middlewares() []config.MiddlewareConfig {
	return nil
}

func (m *InvitationModule) RegisterHooks(events types.EventBus) error {
	return nil
}

func (m *InvitationModule) Dependencies() []string {
	return []string{string(types.CoreModule)}
}

func (m *InvitationModule) OpenAPISpecs() []byte {
	return openapiSpec
}

func (m *InvitationModule) Migrations() types.ModuleMigrations {
	return utils.ParseMigrations(migrationFS)
}
