// Package team is the team module: nested teams inside organizations. A
// team belongs to one organization, may sit beneath another team of it, up
// to models.MaxTeamDepth levels, and holds members of that organization as
// leads or members. Leads manage their team and everything beneath it.
//
// Permission checks for the application's own resources inside a team are
// rbac's: with rbac.Config.Teams, a role held on a team applies to that team
// and every team beneath it (rbac.InTeam, rbac.TeamParam, rbac.TeamFrom).
package team

import (
	"context"
	"embed"

	"github.com/bete7512/goauth/internal/modules/team/handlers"
	"github.com/bete7512/goauth/internal/modules/team/services"
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

var _ config.Module = (*TeamModule)(nil)

// DefaultMaxTeams is the default limit of teams per organization.
const DefaultMaxTeams = 500

// Config configures the team module.
type Config struct {
	// MaxTeams limits the teams of one organization. Default: 500.
	MaxTeams int
	// Storage replaces the storage backend's team store.
	Storage types.TeamStorage
}

// TeamModule is the team module.
type TeamModule struct {
	config  Config
	deps    config.ModuleDependencies
	service services.TeamService
	handler *handlers.Handler
}

// New creates the team module. Pass nil for the defaults.
func New(cfg *Config) *TeamModule {
	m := &TeamModule{}
	if cfg != nil {
		m.config = *cfg
	}
	if m.config.MaxTeams <= 0 {
		m.config.MaxTeams = DefaultMaxTeams
	}
	return m
}

// Name returns the module identifier.
func (m *TeamModule) Name() string { return string(types.TeamModule) }

// Init wires the module to storage.
func (m *TeamModule) Init(_ context.Context, deps config.ModuleDependencies) error {
	store := m.config.Storage
	if store == nil {
		store = deps.Storage.Team()
	}
	if store == nil {
		return config.ErrConfig("team: storage is not available; use a storage backend that provides Team() or set Config.Storage")
	}
	orgs := deps.Storage.Organization()
	if orgs == nil {
		return config.ErrConfig("team: organization storage is not available; register the organization module")
	}
	m.deps = deps
	m.service = services.NewTeamService(deps, services.Stores{
		Teams: store, Orgs: orgs.Organizations(), Members: orgs.Members(), Users: deps.Storage.Core().Users(),
	}, m.config.MaxTeams)
	m.handler = handlers.New(m.service, deps.Storage.Core().Users())
	return nil
}

// Routes returns the team API under /org/{orgId}/teams.
func (m *TeamModule) Routes() []config.RouteInfo {
	if m.handler == nil {
		return nil
	}
	return m.handler.Routes()
}

// Middlewares returns nil.
func (m *TeamModule) Middlewares() []config.MiddlewareConfig { return nil }

// RegisterHooks keeps teams in step with organizations: a member who leaves
// an organization leaves its teams, a deleted organization loses its teams,
// and a deleted user leaves every team. Nothing relies on these: a team
// membership only counts while the organization membership it was made for
// exists.
func (m *TeamModule) RegisterHooks(events types.EventBus) error {
	if events == nil {
		return nil
	}
	events.Subscribe(types.EventOrgMemberRemoved, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		data, ok := types.EventDataAs[*types.OrgMemberEventData](event)
		if !ok || data == nil || m.service == nil {
			return nil
		}
		if err := m.service.RemoveOrgMember(ctx, data.OrgID, data.UserID); err != nil {
			m.deps.Logger.Warnf("team: failed to remove former member %s from the teams of organization %s: %v", data.UserID, data.OrgID, err)
		}
		return nil
	}))
	events.Subscribe(types.EventOrgDeleted, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		data, ok := types.EventDataAs[*types.OrgEventData](event)
		if !ok || data == nil || data.Organization == nil || m.service == nil {
			return nil
		}
		if err := m.service.RemoveOrganization(ctx, data.Organization.ID); err != nil {
			m.deps.Logger.Warnf("team: failed to remove the teams of deleted organization %s: %v", data.Organization.ID, err)
		}
		return nil
	}))
	events.Subscribe(types.EventAdminUserDeleted, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		data, ok := types.EventDataAs[map[string]interface{}](event)
		if !ok || m.service == nil {
			return nil
		}
		userID, _ := data["target_id"].(string)
		if err := m.service.RemoveUser(ctx, userID); err != nil {
			m.deps.Logger.Warnf("team: failed to remove deleted user %s from their teams: %v", userID, err)
		}
		return nil
	}))
	return nil
}

// Dependencies returns core and organization.
func (m *TeamModule) Dependencies() []string {
	return []string{string(types.CoreModule), string(types.OrganizationModule)}
}

// OpenAPISpecs returns the module's OpenAPI document.
func (m *TeamModule) OpenAPISpecs() []byte { return openapiSpec }

// Migrations returns the teams and team_members tables.
func (m *TeamModule) Migrations() types.ModuleMigrations { return utils.ParseMigrations(migrationFS) }

// ServiceOf returns the team service, or nil before Init. It is a function
// rather than a method so that it is reachable only from inside GoAuth, for
// the ui module and rbac.
func ServiceOf(m *TeamModule) services.TeamService {
	if m == nil {
		return nil
	}
	return m.service
}
