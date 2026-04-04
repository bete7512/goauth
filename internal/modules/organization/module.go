package organization

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/organization/handlers"
	"github.com/bete7512/goauth/internal/modules/organization/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/organization/middlewares"
	"github.com/bete7512/goauth/internal/modules/organization/services"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

var (
	//go:embed docs/openapi.yml
	openapiSpec []byte

	//go:embed migrations
	migrationFS embed.FS
)

var _ config.Module = (*OrganizationModule)(nil)

type OrganizationModule struct {
	deps              config.ModuleDependencies
	config            *Config
	orgHandler        *handlers.OrgHandler
	memberHandler     *handlers.MemberHandler
	invitationHandler *handlers.InvitationHandler
	orgAuthMiddleware *middlewares.OrgAuthMiddleware
}

func New(cfg *Config) *OrganizationModule {
	if cfg == nil {
		cfg = &Config{}
	}
	cfg.applyDefaults()
	return &OrganizationModule{config: cfg}
}

func (m *OrganizationModule) Name() string {
	return string(types.OrganizationModule)
}

func (m *OrganizationModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	orgStorage := deps.Storage.Organization()
	if orgStorage == nil {
		return fmt.Errorf("organization storage is not available")
	}

	orgRepo := orgStorage.Organizations()
	memberRepo := orgStorage.Members()
	invitationRepo := orgStorage.Invitations()
	userRepo := deps.Storage.Core().Users()

	// Create services
	orgService := services.NewOrgService(deps, orgRepo, memberRepo, userRepo)
	memberService := services.NewMemberService(deps, memberRepo, orgRepo, userRepo, m.config.MaxMembersPerOrg)
	invitationService := services.NewInvitationService(
		deps, invitationRepo, memberRepo, orgRepo, userRepo,
		m.config.InvitationExpiry, m.config.InvitationCallbackURL, m.config.MaxMembersPerOrg,
	)

	// Create handlers
	m.orgHandler = handlers.NewOrgHandler(deps, orgService)
	m.memberHandler = handlers.NewMemberHandler(deps, memberService)
	m.invitationHandler = handlers.NewInvitationHandler(deps, invitationService)

	// Create middleware
	m.orgAuthMiddleware = middlewares.NewOrgAuthMiddleware(orgRepo, memberRepo, deps.Logger)

	// Register auth interceptor for org claims enrichment
	deps.AuthInterceptors.Register("organization", func(ctx context.Context, params *types.InterceptParams) (*types.InterceptResult, error) {
		memberships, err := memberRepo.ListByUser(ctx, params.User.ID)
		if err != nil || len(memberships) == 0 {
			return &types.InterceptResult{}, nil
		}

		// Build org info list with names from the org repo
		orgInfos := make([]types.OrgInfo, 0, len(memberships))
		for _, m := range memberships {
			info := types.OrgInfo{ID: m.OrgID, Role: m.Role}
			org, orgErr := orgRepo.FindByID(ctx, m.OrgID)
			if orgErr == nil && org != nil {
				info.Name = org.Name
				info.Slug = org.Slug
			}
			orgInfos = append(orgInfos, info)
		}

		// Pick default org: always use first membership
		active := orgInfos[0]

		claims := map[string]interface{}{
			"active_org_id":   active.ID,
			"org_role":        active.Role,
			"org_memberships": orgInfos, // also embedded in JWT for middleware use
		}

		return &types.InterceptResult{
			Claims: claims,
			ResponseData: map[string]interface{}{
				"organizations":       orgInfos,
				"active_organization": active,
			},
		}, nil
	}, 50) // Lower priority than 2FA

	deps.Logger.Info("Organization module initialized")
	return nil
}

func (m *OrganizationModule) Routes() []config.RouteInfo {
	return []config.RouteInfo{
		// No org context needed (user-level)
		{Name: string(types.RouteOrgCreate), Path: "/org", Method: http.MethodPost, Handler: m.orgHandler.Create, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteOrgMyOrgs), Path: "/org/my", Method: http.MethodGet, Handler: m.orgHandler.MyOrgs, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteOrgSwitch), Path: "/org/switch", Method: http.MethodPost, Handler: m.orgHandler.Switch, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteOrgMyInvitations), Path: "/org/my/invitations", Method: http.MethodGet, Handler: m.invitationHandler.MyInvitations, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteOrgAcceptInvitation), Path: "/org/invitations/accept", Method: http.MethodPost, Handler: m.invitationHandler.AcceptInvitation, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},
		{Name: string(types.RouteOrgDeclineInvitation), Path: "/org/invitations/decline", Method: http.MethodPost, Handler: m.invitationHandler.DeclineInvitation, Middlewares: []types.MiddlewareName{types.MiddlewareAuth}},

		// Org context required (org middleware applied)
		{Name: string(types.RouteOrgGet), Path: "/org/{orgId}", Method: http.MethodGet, Handler: m.orgHandler.Get, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
		{Name: string(types.RouteOrgUpdate), Path: "/org/{orgId}", Method: http.MethodPut, Handler: m.orgHandler.Update, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
		{Name: string(types.RouteOrgDelete), Path: "/org/{orgId}", Method: http.MethodDelete, Handler: m.orgHandler.Delete, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
		{Name: string(types.RouteOrgListMembers), Path: "/org/{orgId}/members", Method: http.MethodGet, Handler: m.memberHandler.ListMembers, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
		{Name: string(types.RouteOrgGetMember), Path: "/org/{orgId}/members/{userId}", Method: http.MethodGet, Handler: m.memberHandler.GetMember, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
		{Name: string(types.RouteOrgUpdateMember), Path: "/org/{orgId}/members/{userId}", Method: http.MethodPut, Handler: m.memberHandler.UpdateMember, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
		{Name: string(types.RouteOrgRemoveMember), Path: "/org/{orgId}/members/{userId}", Method: http.MethodDelete, Handler: m.memberHandler.RemoveMember, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
		{Name: string(types.RouteOrgInvite), Path: "/org/{orgId}/invite", Method: http.MethodPost, Handler: m.invitationHandler.Invite, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
		{Name: string(types.RouteOrgListInvitations), Path: "/org/{orgId}/invitations", Method: http.MethodGet, Handler: m.invitationHandler.ListInvitations, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
		{Name: string(types.RouteOrgCancelInvitation), Path: "/org/{orgId}/invitations/{invId}", Method: http.MethodDelete, Handler: m.invitationHandler.CancelInvitation, Middlewares: []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareOrgAuth}},
	}
}

func (m *OrganizationModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{
		{
			Name:       types.MiddlewareOrgAuth,
			Middleware: m.orgAuthMiddleware.Middleware,
			Priority:   45,                  // Below auth (50), above 2FA (40)
			ApplyTo:    []types.RouteName{}, // Applied via route's Middlewares field, not pattern
			Global:     false,
		},
	}
}

func (m *OrganizationModule) RegisterHooks(events types.EventBus) error {
	if m.config.AutoCreateOrg {
		events.Subscribe(types.EventAfterSignup, types.EventHandler(func(ctx context.Context, event *types.Event) error {
			data, ok := types.EventDataAs[*types.UserEventData](event)
			if !ok {
				m.deps.Logger.Warn("Failed to extract UserEventData for auto-create org")
				return nil
			}

			user := data.User
			orgName := m.buildOrgName(user)

			orgStorage := m.deps.Storage.Organization()
			if orgStorage == nil {
				return nil
			}

			orgService := services.NewOrgService(m.deps,
				orgStorage.Organizations(),
				orgStorage.Members(),
				m.deps.Storage.Core().Users(),
			)

			_, authErr := orgService.Create(ctx, user.ID, &dto.CreateOrgRequest{Name: orgName})
			if authErr != nil {
				m.deps.Logger.Error("Failed to auto-create organization", "user_id", user.ID, "error", authErr.Message)
			} else {
				m.deps.Logger.Info("Auto-created organization for user", "user_id", user.ID, "org_name", orgName)
			}

			return nil
		}))
	}

	return nil
}

func (m *OrganizationModule) Dependencies() []string {
	return []string{string(types.CoreModule)}
}

func (m *OrganizationModule) OpenAPISpecs() []byte {
	return openapiSpec
}

func (m *OrganizationModule) Migrations() types.ModuleMigrations {
	return utils.ParseMigrations(migrationFS)
}

func (m *OrganizationModule) buildOrgName(user *models.User) string {
	name := m.config.DefaultOrgNamePattern
	replacer := strings.NewReplacer(
		"{name}", user.Name,
		"{email}", user.Email,
		"{username}", user.Username,
	)
	result := replacer.Replace(name)
	if result == "" || result == "'s workspace" {
		result = user.Email + "'s workspace"
	}
	return result
}
