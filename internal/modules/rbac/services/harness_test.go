package services_test

import (
	"context"

	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

const (
	orgID     = "org-1"
	userID    = "user-1"
	otherUser = "user-2"
	memberID  = "membership-1"
)

// harness wires the three services to mocked repositories.
type harness struct {
	users       *mocks.MockUserRepository
	orgs        *mocks.MockOrganizationRepository
	members     *mocks.MockOrganizationMemberRepository
	roles       *mocks.MockRoleRepository
	assignments *mocks.MockRoleAssignmentRepository
	events      *mocks.MockEventBus

	settings services.Settings
	access   services.AccessService
	roleSvc  services.RoleService
	assign   services.AssignmentService
}

func testSettings() services.Settings {
	return services.Settings{
		Organizations: true,
		Roles: map[access.ScopeType]map[string]access.Role{
			access.ScopeGlobal: {
				access.RoleSuperAdmin: {Key: access.RoleSuperAdmin, Name: "Super admin", Scope: access.ScopeGlobal, Grants: []string{"*", "goauth.*:*"}},
				"viewer":              {Key: "viewer", Name: "Viewer", Grants: []string{"*:read"}},
			},
			access.ScopeOrg: {
				access.RoleOwner:  {Key: access.RoleOwner, Name: "Owner", Scope: access.ScopeOrg, Grants: []string{"*", "goauth.*:*"}},
				access.RoleAdmin:  {Key: access.RoleAdmin, Name: "Admin", Scope: access.ScopeOrg, Grants: []string{"*", access.PermRolesRead, access.PermAssignmentsRead}},
				access.RoleMember: {Key: access.RoleMember, Name: "Member", Scope: access.ScopeOrg, Grants: []string{}},
				"viewer":          {Key: "viewer", Name: "Viewer", Grants: []string{"*:read"}},
			},
		},
		MaxRolesPerScope: 3,
		MaxGrantsPerRole: 4,
		MaxRolesPerUser:  2,
	}
}

func newHarness(s *suite.Suite, mutate ...func(*services.Settings)) *harness {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	h := &harness{
		users:       mocks.NewMockUserRepository(ctrl),
		orgs:        mocks.NewMockOrganizationRepository(ctrl),
		members:     mocks.NewMockOrganizationMemberRepository(ctrl),
		roles:       mocks.NewMockRoleRepository(ctrl),
		assignments: mocks.NewMockRoleAssignmentRepository(ctrl),
		events:      mocks.NewMockEventBus(ctrl),
		settings:    testSettings(),
	}
	for _, fn := range mutate {
		fn(&h.settings)
	}

	logger := mocks.NewMockLogger(ctrl)
	logger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()
	logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()
	logger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()

	store := mocks.NewMockRBACStorage(ctrl)
	store.EXPECT().Roles().Return(h.roles).AnyTimes()
	store.EXPECT().Assignments().Return(h.assignments).AnyTimes()
	// A transaction runs its function against the same repositories.
	store.EXPECT().WithTransaction(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, fn func(types.RBACStorage) error) error { return fn(store) },
	).AnyTimes()

	deps := config.ModuleDependencies{
		Events:           h.events,
		Logger:           logger,
		AuthInterceptors: interceptor.NewRegistry(),
	}
	stores := services.Stores{RBAC: store, Users: h.users, Orgs: h.orgs, Members: h.members}
	accessService := services.NewAccessService(deps, stores, h.settings)
	h.access = accessService
	h.roleSvc = services.NewRoleService(deps, stores, h.settings, accessService)
	h.assign = services.NewAssignmentService(deps, stores, h.settings, accessService)
	return h
}

// --- expectations shared by the suites ---

func (h *harness) user(id string, mutate ...func(*models.User)) {
	user := &models.User{ID: id, Email: id + "@example.com", Active: true}
	for _, fn := range mutate {
		fn(user)
	}
	h.users.EXPECT().FindByID(gomock.Any(), id).Return(user, nil).AnyTimes()
}

func (h *harness) noUser(id string) {
	h.users.EXPECT().FindByID(gomock.Any(), id).Return(nil, models.ErrNotFound).AnyTimes()
}

func (h *harness) org(active bool) {
	h.orgs.EXPECT().FindByID(gomock.Any(), orgID).Return(&models.Organization{ID: orgID, Active: active}, nil).AnyTimes()
}

func (h *harness) member(user, membership, role string) {
	h.members.EXPECT().FindByOrgAndUser(gomock.Any(), orgID, user).
		Return(&models.OrganizationMember{ID: membership, OrgID: orgID, UserID: user, Role: role}, nil).AnyTimes()
}

func (h *harness) notMember(user string) {
	h.members.EXPECT().FindByOrgAndUser(gomock.Any(), orgID, user).Return(nil, models.ErrNotFound).AnyTimes()
}

// assigned makes the repository return rows for every lookup of the user's
// assignments, whichever scopes are asked for.
func (h *harness) assigned(user string, rows ...*models.RoleAssignment) {
	h.assignments.EXPECT().ListByUser(gomock.Any(), user, gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, scopes []models.RoleScopeRef) ([]*models.RoleAssignment, error) {
			var out []*models.RoleAssignment
			for _, row := range rows {
				for _, scope := range scopes {
					if row.ScopeType == scope.Type && row.ScopeID == scope.ID {
						out = append(out, row)
					}
				}
			}
			return out, nil
		},
	).AnyTimes()
}

func globalRow(user, key string) *models.RoleAssignment {
	return &models.RoleAssignment{UserID: user, ScopeType: models.RoleScopeGlobal, RoleKey: key}
}

func orgRow(user, key, membership string) *models.RoleAssignment {
	return &models.RoleAssignment{UserID: user, ScopeType: models.RoleScopeOrg, ScopeID: orgID, RoleKey: key, MembershipID: membership}
}

func storedRole(org, key string, grants ...string) *models.Role {
	return &models.Role{ID: "role-" + org + "-" + key, OrgID: org, Key: key, Name: key, Grants: grants}
}

func actor(id string) *services.Actor {
	return &services.Actor{Principal: types.Principal{UserID: id}}
}

func strPtr(value string) *string { return &value }
