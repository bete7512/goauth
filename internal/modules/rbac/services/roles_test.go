package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type RoleServiceSuite struct {
	suite.Suite
}

func TestRoleServiceSuite(t *testing.T) {
	suite.Run(t, new(RoleServiceSuite))
}

// owner makes userID the owner of the organization, who may manage roles.
func owner(h *harness) {
	h.user(userID)
	h.org(true)
	h.member(userID, memberID, "owner")
	h.assigned(userID)
}

func listOpts(field, dir string, offset, limit int) models.RoleListOpts {
	opts := models.RoleListOpts{ListingOpts: models.ListingOpts{SortField: field, SortDir: dir, Offset: offset, Limit: limit}}
	opts.Normalize(100)
	return opts
}

func keysOf(views []*services.RoleView) []string {
	keys := make([]string, 0, len(views))
	for _, view := range views {
		keys = append(keys, view.Key)
	}
	return keys
}

// --- Create ---

func (s *RoleServiceSuite) TestCreate_Success() {
	h := newHarness(&s.Suite)
	owner(h)
	h.roles.EXPECT().CountByOrg(gomock.Any(), orgID).Return(int64(0), nil)
	h.roles.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, role *models.Role) error {
		s.Equal(orgID, role.OrgID)
		s.Equal("billing", role.Key)
		s.Equal("Billing", role.Name)
		s.Equal(models.StringList{"invoice:*", "project:read"}, role.Grants, "grants are canonical, unique and sorted")
		s.Equal(userID, role.CreatedBy)
		role.CreatedAt = time.Now()
		return nil
	})
	h.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleCreated, gomock.Any()).Return(nil)

	view, authErr := h.roleSvc.Create(context.Background(), actor(userID), access.OrgScope(orgID), services.RoleInput{
		Key: "billing", Name: "  Billing ", Grants: []string{" project:read", "invoice:*", "project:read"},
	})
	s.Nil(authErr)
	s.Equal("billing", view.Key)
	s.False(view.System)
	s.Equal(access.ScopeOrg, view.Scope)
	s.Equal(orgID, view.OrgID)
}

func (s *RoleServiceSuite) TestCreate_RejectsBadInput() {
	cases := []struct {
		name  string
		input services.RoleInput
		code  types.ErrorCode
	}{
		{"uppercase key", services.RoleInput{Key: "Billing", Name: "x"}, types.ErrRBACInvalidRole},
		{"key with space", services.RoleInput{Key: "bill ing", Name: "x"}, types.ErrRBACInvalidRole},
		{"empty key", services.RoleInput{Key: "", Name: "x"}, types.ErrRBACInvalidRole},
		{"super admin key", services.RoleInput{Key: access.RoleSuperAdmin, Name: "x"}, types.ErrRBACRoleSystem},
		{"membership key", services.RoleInput{Key: access.RoleAdmin, Name: "x"}, types.ErrRBACRoleSystem},
		{"key of a role defined in code", services.RoleInput{Key: "viewer", Name: "x"}, types.ErrRBACRoleExists},
		{"blank name", services.RoleInput{Key: "billing", Name: "   "}, types.ErrRBACInvalidRole},
		{"malformed grant", services.RoleInput{Key: "billing", Name: "x", Grants: []string{"invoice"}}, types.ErrRBACInvalidRole},
		{"too many grants", services.RoleInput{Key: "billing", Name: "x", Grants: []string{"a:read", "b:read", "c:read", "d:read", "e:read"}}, types.ErrRBACLimitExceeded},
	}
	for _, c := range cases {
		h := newHarness(&s.Suite)
		owner(h)
		_, authErr := h.roleSvc.Create(context.Background(), actor(userID), access.OrgScope(orgID), c.input)
		s.NotNil(authErr, c.name)
		s.Equal(c.code, authErr.Code, c.name)
	}
}

func (s *RoleServiceSuite) TestCreate_LimitAndConflict() {
	h := newHarness(&s.Suite)
	owner(h)
	h.roles.EXPECT().CountByOrg(gomock.Any(), orgID).Return(int64(3), nil)
	_, authErr := h.roleSvc.Create(context.Background(), actor(userID), access.OrgScope(orgID), services.RoleInput{Key: "billing", Name: "x"})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACLimitExceeded, authErr.Code)

	h = newHarness(&s.Suite)
	owner(h)
	h.roles.EXPECT().CountByOrg(gomock.Any(), orgID).Return(int64(0), nil)
	h.roles.EXPECT().Create(gomock.Any(), gomock.Any()).Return(models.ErrConflict)
	_, authErr = h.roleSvc.Create(context.Background(), actor(userID), access.OrgScope(orgID), services.RoleInput{Key: "billing", Name: "x"})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACRoleExists, authErr.Code)
}

func (s *RoleServiceSuite) TestCreate_NeedsThePermissionAndTheGrants() {
	// An admin holds "*" but not the permission to write roles.
	h := newHarness(&s.Suite)
	h.user(userID)
	h.org(true)
	h.member(userID, memberID, "admin")
	h.assigned(userID)
	_, authErr := h.roleSvc.Create(context.Background(), actor(userID), access.OrgScope(orgID), services.RoleInput{Key: "billing", Name: "x"})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACPermissionDenied, authErr.Code)

	// A delegate may write roles, but only within what the delegate holds.
	h = newHarness(&s.Suite)
	h.user(userID)
	h.org(true)
	h.member(userID, memberID, "member")
	h.assigned(userID, orgRow(userID, "delegate", memberID))
	h.roles.EXPECT().FindByKeys(gomock.Any(), orgID, []string{"delegate"}).
		Return([]*models.Role{storedRole(orgID, "delegate", "goauth.roles:*", "invoice:read")}, nil).AnyTimes()
	_, authErr = h.roleSvc.Create(context.Background(), actor(userID), access.OrgScope(orgID), services.RoleInput{Key: "billing", Name: "x", Grants: []string{"invoice:read", "invoice:approve"}})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACGrantNotHeld, authErr.Code)
	s.Contains(authErr.Message, "invoice:approve")
}

func (s *RoleServiceSuite) TestCreate_ScopeMustExist() {
	h := newHarness(&s.Suite)
	h.orgs.EXPECT().FindByID(gomock.Any(), orgID).Return(nil, models.ErrNotFound)
	_, authErr := h.roleSvc.Create(context.Background(), actor(userID), access.OrgScope(orgID), services.RoleInput{Key: "billing", Name: "x"})
	s.NotNil(authErr)
	s.Equal(types.ErrOrgNotFound, authErr.Code)

	h = newHarness(&s.Suite)
	h.org(false)
	_, authErr = h.roleSvc.Create(context.Background(), actor(userID), access.OrgScope(orgID), services.RoleInput{Key: "billing", Name: "x"})
	s.NotNil(authErr)
	s.Equal(types.ErrOrgNotFound, authErr.Code, "an inactive organization cannot be managed")

	h = newHarness(&s.Suite)
	h.org(true)
	_, authErr = h.roleSvc.Create(context.Background(), &services.Actor{}, access.OrgScope(orgID), services.RoleInput{Key: "billing", Name: "x"})
	s.NotNil(authErr)
	s.Equal(types.ErrUnauthorized, authErr.Code)
}

// Code that calls the service without an actor is trusted: no permission is
// needed and the role may grant anything.
func (s *RoleServiceSuite) TestCreate_TrustedCodeSkipsPermissionChecks() {
	h := newHarness(&s.Suite)
	h.roles.EXPECT().CountByOrg(gomock.Any(), "").Return(int64(0), nil)
	h.roles.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
	h.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleCreated, gomock.Any()).Return(nil)

	view, authErr := h.roleSvc.Create(context.Background(), nil, access.GlobalScope(), services.RoleInput{Key: "root", Name: "Root", Grants: []string{"*", "goauth.*:*"}})
	s.Nil(authErr)
	s.Equal(access.ScopeGlobal, view.Scope)
	s.Empty(view.CreatedBy)
}

// --- Update ---

func (s *RoleServiceSuite) TestUpdate_Success() {
	h := newHarness(&s.Suite)
	owner(h)
	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "billing").Return(storedRole(orgID, "billing", "invoice:read"), nil)
	h.roles.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, role *models.Role) error {
		s.Equal("Billing team", role.Name)
		s.Equal(models.StringList{"invoice:*"}, role.Grants)
		return nil
	})
	h.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleUpdated, gomock.Any()).Return(nil)

	grants := []string{"invoice:*"}
	view, authErr := h.roleSvc.Update(context.Background(), actor(userID), access.OrgScope(orgID), "billing", services.RolePatch{Name: strPtr("Billing team"), Grants: &grants})
	s.Nil(authErr)
	s.Equal("Billing team", view.Name)
	s.Equal([]string{"invoice:*"}, view.Grants)
}

func (s *RoleServiceSuite) TestUpdate_Refusals() {
	h := newHarness(&s.Suite)
	owner(h)
	for _, key := range []string{"viewer", access.RoleOwner, access.RoleSuperAdmin} {
		_, authErr := h.roleSvc.Update(context.Background(), actor(userID), access.OrgScope(orgID), key, services.RolePatch{Name: strPtr("x")})
		s.NotNil(authErr, key)
		s.Equal(types.ErrRBACRoleSystem, authErr.Code, key)
	}

	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "missing").Return(nil, models.ErrNotFound)
	_, authErr := h.roleSvc.Update(context.Background(), actor(userID), access.OrgScope(orgID), "missing", services.RolePatch{Name: strPtr("x")})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACRoleNotFound, authErr.Code)

	_, authErr = h.roleSvc.Update(context.Background(), actor(userID), access.OrgScope(orgID), "Not A Key", services.RolePatch{Name: strPtr("x")})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACRoleNotFound, authErr.Code, "a malformed key is never looked up")

	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "billing").Return(storedRole(orgID, "billing", "invoice:read"), nil)
	_, authErr = h.roleSvc.Update(context.Background(), actor(userID), access.OrgScope(orgID), "billing", services.RolePatch{Name: strPtr(" ")})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACInvalidRole, authErr.Code)

	// The repository answered with a role of another organization.
	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "foreign").Return(storedRole("org-2", "foreign", "invoice:read"), nil)
	_, authErr = h.roleSvc.Update(context.Background(), actor(userID), access.OrgScope(orgID), "foreign", services.RolePatch{Name: strPtr("x")})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACRoleNotFound, authErr.Code)
}

// A role that grants more than the caller holds cannot be changed by the
// caller at all, not even to remove grants from it.
func (s *RoleServiceSuite) TestUpdate_CallerMustHoldTheOldAndTheNewGrants() {
	setup := func() *harness {
		h := newHarness(&s.Suite)
		h.user(userID)
		h.org(true)
		h.member(userID, memberID, "member")
		h.assigned(userID, orgRow(userID, "delegate", memberID))
		h.roles.EXPECT().FindByKeys(gomock.Any(), orgID, []string{"delegate"}).
			Return([]*models.Role{storedRole(orgID, "delegate", "goauth.roles:*", "invoice:read")}, nil).AnyTimes()
		return h
	}

	h := setup()
	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "approver").Return(storedRole(orgID, "approver", "invoice:approve"), nil)
	empty := []string{}
	_, authErr := h.roleSvc.Update(context.Background(), actor(userID), access.OrgScope(orgID), "approver", services.RolePatch{Grants: &empty})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACGrantNotHeld, authErr.Code, "old grants")

	h = setup()
	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "reader").Return(storedRole(orgID, "reader", "invoice:read"), nil)
	wider := []string{"invoice:*"}
	_, authErr = h.roleSvc.Update(context.Background(), actor(userID), access.OrgScope(orgID), "reader", services.RolePatch{Grants: &wider})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACGrantNotHeld, authErr.Code, "new grants")
}

// --- Delete ---

func (s *RoleServiceSuite) TestDelete_RemovesTheAssignmentsWithTheRole() {
	h := newHarness(&s.Suite)
	owner(h)
	role := storedRole(orgID, "billing", "invoice:*")
	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "billing").Return(role, nil)
	gomock.InOrder(
		h.assignments.EXPECT().DeleteByRole(gomock.Any(), models.RoleScopeOrg, orgID, "billing").Return(nil),
		h.roles.EXPECT().Delete(gomock.Any(), role.ID).Return(nil),
	)
	h.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleDeleted, gomock.Any()).Return(nil)

	s.Nil(h.roleSvc.Delete(context.Background(), actor(userID), access.OrgScope(orgID), "billing"))
}

func (s *RoleServiceSuite) TestDelete_Refusals() {
	h := newHarness(&s.Suite)
	owner(h)
	authErr := h.roleSvc.Delete(context.Background(), actor(userID), access.OrgScope(orgID), "viewer")
	s.NotNil(authErr)
	s.Equal(types.ErrRBACRoleSystem, authErr.Code)

	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "billing").Return(storedRole(orgID, "billing"), nil)
	h.assignments.EXPECT().DeleteByRole(gomock.Any(), models.RoleScopeOrg, orgID, "billing").Return(errors.New("db down"))
	authErr = h.roleSvc.Delete(context.Background(), actor(userID), access.OrgScope(orgID), "billing")
	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code, "the role is not deleted when its assignments could not be")
}

// --- List and Get ---

func (s *RoleServiceSuite) TestList_MergesRolesFromCodeAndStorage() {
	h := newHarness(&s.Suite)
	owner(h)
	older, newer := storedRole(orgID, "billing", "invoice:*"), storedRole(orgID, "auditor", "audit:read")
	older.CreatedAt, newer.CreatedAt = time.Unix(100, 0), time.Unix(200, 0)
	older.Name, newer.Name = "Billing", "Auditor"
	h.roles.EXPECT().ListByOrg(gomock.Any(), orgID).Return([]*models.Role{older, newer, storedRole("org-2", "foreign")}, nil).AnyTimes()
	ctx, scope := context.Background(), access.OrgScope(orgID)

	views, total, authErr := h.roleSvc.List(ctx, actor(userID), scope, listOpts("key", "asc", 0, 20))
	s.Nil(authErr)
	s.EqualValues(6, total, "a role of another organization is left out")
	s.Equal([]string{"admin", "auditor", "billing", "member", "owner", "viewer"}, keysOf(views))
	s.True(views[0].System)
	s.True(views[0].Implied)
	s.False(views[5].Implied, "a role defined in code that is not a membership role can be assigned")
	s.False(views[1].System)

	views, _, authErr = h.roleSvc.List(ctx, actor(userID), scope, listOpts("created_at", "desc", 0, 2))
	s.Nil(authErr)
	s.Equal([]string{"auditor", "billing"}, keysOf(views), "newest stored role first; roles from code have no creation time")

	views, total, authErr = h.roleSvc.List(ctx, actor(userID), scope, listOpts("key", "asc", 4, 20))
	s.Nil(authErr)
	s.EqualValues(6, total)
	s.Equal([]string{"owner", "viewer"}, keysOf(views))

	views, total, authErr = h.roleSvc.List(ctx, actor(userID), scope, listOpts("key", "asc", 50, 20))
	s.Nil(authErr)
	s.EqualValues(6, total)
	s.Empty(views)

	filtered := listOpts("name", "asc", 0, 20)
	filtered.Query = "BILL"
	views, total, authErr = h.roleSvc.List(ctx, actor(userID), scope, filtered)
	s.Nil(authErr)
	s.EqualValues(1, total)
	s.Equal([]string{"billing"}, keysOf(views))
}

func (s *RoleServiceSuite) TestGet() {
	h := newHarness(&s.Suite)
	owner(h)
	ctx, scope := context.Background(), access.OrgScope(orgID)

	view, authErr := h.roleSvc.Get(ctx, actor(userID), scope, "owner")
	s.Nil(authErr)
	s.True(view.System)
	s.True(view.Implied)
	s.Equal([]string{"*", "goauth.*:*"}, view.Grants)

	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "billing").Return(storedRole(orgID, "billing", "invoice:*"), nil)
	view, authErr = h.roleSvc.Get(ctx, actor(userID), scope, "billing")
	s.Nil(authErr)
	s.False(view.System)

	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "missing").Return(nil, models.ErrNotFound)
	_, authErr = h.roleSvc.Get(ctx, actor(userID), scope, "missing")
	s.NotNil(authErr)
	s.Equal(types.ErrRBACRoleNotFound, authErr.Code)
}

func (s *RoleServiceSuite) TestRemoveOrganization() {
	h := newHarness(&s.Suite)
	gomock.InOrder(
		h.assignments.EXPECT().DeleteByScope(gomock.Any(), models.RoleScopeOrg, orgID).Return(nil),
		h.roles.EXPECT().DeleteByOrg(gomock.Any(), orgID).Return(nil),
	)
	s.NoError(h.roleSvc.RemoveOrganization(context.Background(), orgID))
	s.NoError(h.roleSvc.RemoveOrganization(context.Background(), ""), "an empty ID would delete the application's own roles")
}

func (s *RoleServiceSuite) TestValidRoleKey() {
	for _, key := range []string{"a", "billing", "billing-manager", "tier_2", "0day"} {
		s.True(services.ValidRoleKey(key), key)
	}
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	for _, key := range []string{"", "Billing", "bill ing", "-x", "_x", "a.b", "a:b", "a/b", string(long)} {
		s.False(services.ValidRoleKey(key), key)
	}
}
