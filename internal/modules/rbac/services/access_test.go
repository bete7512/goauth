package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type AccessServiceSuite struct {
	suite.Suite
}

func TestAccessServiceSuite(t *testing.T) {
	suite.Run(t, new(AccessServiceSuite))
}

// --- Holding ---

func (s *AccessServiceSuite) TestHolding_UnknownOrInactiveUserHoldsNothing() {
	h := newHarness(&s.Suite)
	h.noUser(userID)
	h.user(otherUser, func(u *models.User) { u.Active = false; u.IsSuperAdmin = true })

	holding, authErr := h.access.Holding(context.Background(), userID, access.GlobalScope())
	s.Nil(authErr)
	s.Empty(holding.Roles)
	s.Empty(holding.Grants)

	holding, authErr = h.access.Holding(context.Background(), otherUser, access.GlobalScope())
	s.Nil(authErr)
	s.Empty(holding.Roles, "an inactive super admin holds nothing")

	holding, authErr = h.access.Holding(context.Background(), "", access.GlobalScope())
	s.Nil(authErr)
	s.Empty(holding.Grants)
}

func (s *AccessServiceSuite) TestHolding_SuperAdminHoldsEverything() {
	h := newHarness(&s.Suite)
	h.user(userID, func(u *models.User) { u.IsSuperAdmin = true })
	h.assigned(userID)

	holding, authErr := h.access.Holding(context.Background(), userID, access.GlobalScope())
	s.Nil(authErr)
	s.Equal([]string{access.RoleSuperAdmin}, holding.RoleKeys())
	s.True(holding.Roles[0].Implied)
	s.True(holding.Grants.Allows("invoice:delete"))
	s.True(holding.Grants.Allows(access.PermAssignmentsWrite))
}

func (s *AccessServiceSuite) TestHolding_GlobalRolesDefinedInCodeAndStored() {
	h := newHarness(&s.Suite)
	h.user(userID)
	h.assigned(userID, globalRow(userID, "viewer"), globalRow(userID, "auditor"), globalRow(userID, "deleted-role"))
	h.roles.EXPECT().FindByKeys(gomock.Any(), "", gomock.InAnyOrder([]string{"auditor", "deleted-role"})).
		Return([]*models.Role{storedRole("", "auditor", "audit:read", "NOT A GRANT")}, nil)

	holding, authErr := h.access.Holding(context.Background(), userID, access.GlobalScope())
	s.Nil(authErr)
	s.Equal([]string{"viewer", "auditor"}, holding.RoleKeys(), "a role that no longer exists adds nothing")
	s.True(holding.Roles[0].System)
	s.False(holding.Roles[1].System)
	s.Equal([]string{"*:read", "audit:read"}, holding.Grants.Strings(), "an unreadable grant is dropped")
}

func (s *AccessServiceSuite) TestHolding_OrganizationMembershipAndAssignments() {
	h := newHarness(&s.Suite)
	h.user(userID)
	h.org(true)
	h.member(userID, memberID, "admin")
	h.assigned(userID, globalRow(userID, "viewer"), orgRow(userID, "billing", memberID))
	h.roles.EXPECT().FindByKeys(gomock.Any(), orgID, []string{"billing"}).
		Return([]*models.Role{storedRole(orgID, "billing", "invoice:*")}, nil)

	holding, authErr := h.access.Holding(context.Background(), userID, access.OrgScope(orgID))
	s.Nil(authErr)
	s.Equal([]string{"admin", "viewer", "billing"}, holding.RoleKeys())
	s.Equal(memberID, holding.MembershipID)
	s.Equal(access.ScopeOrg, holding.Roles[0].Scope)
	s.True(holding.Roles[0].Implied)
	s.Equal(access.ScopeGlobal, holding.Roles[1].Scope, "a global role applies inside the organization")
	s.True(holding.Grants.Allows("invoice:approve"))
	s.False(holding.Grants.Allows(access.PermRolesWrite), "an admin cannot manage roles")
	s.True(holding.Grants.Allows(access.PermRolesRead))
}

func (s *AccessServiceSuite) TestHolding_OrganizationAssignmentsCountOnlyForTheirMembership() {
	h := newHarness(&s.Suite)
	h.user(userID)
	h.org(true)
	h.member(userID, "membership-new", "member")
	h.assigned(userID,
		orgRow(userID, "viewer", "membership-old"),      // made for an earlier membership
		orgRow(userID, "owner", "membership-new"),       // implied roles are never taken from a row
		orgRow(userID, "super_admin", "membership-new"), // nor is the super admin role
		&models.RoleAssignment{UserID: otherUser, ScopeType: models.RoleScopeOrg, ScopeID: orgID, RoleKey: "viewer", MembershipID: "membership-new"},
		&models.RoleAssignment{UserID: userID, ScopeType: "team", ScopeID: orgID, RoleKey: "viewer"},
	)

	holding, authErr := h.access.Holding(context.Background(), userID, access.OrgScope(orgID))
	s.Nil(authErr)
	s.Equal([]string{"member"}, holding.RoleKeys())
	s.Empty(holding.Grants)
}

func (s *AccessServiceSuite) TestHolding_NonMemberKeepsOnlyGlobalRoles() {
	h := newHarness(&s.Suite)
	h.user(userID)
	h.notMember(userID)
	h.assigned(userID, globalRow(userID, "viewer"), orgRow(userID, "viewer", memberID))

	holding, authErr := h.access.Holding(context.Background(), userID, access.OrgScope(orgID))
	s.Nil(authErr)
	s.Equal([]string{"viewer"}, holding.RoleKeys())
	s.Equal(access.ScopeGlobal, holding.Roles[0].Scope)
	s.Empty(holding.MembershipID)
}

func (s *AccessServiceSuite) TestHolding_InactiveOrganizationCountsAsNoMembership() {
	h := newHarness(&s.Suite)
	h.user(userID)
	h.org(false)
	h.member(userID, memberID, "owner")
	h.assigned(userID)

	holding, authErr := h.access.Holding(context.Background(), userID, access.OrgScope(orgID))
	s.Nil(authErr)
	s.Empty(holding.Roles)
}

// The organization an access token was issued for was validated when the
// request was authenticated, so it is not loaded again.
func (s *AccessServiceSuite) TestHolding_ActiveOrganizationIsNotLoadedTwice() {
	h := newHarness(&s.Suite)
	h.user(userID)
	h.member(userID, memberID, "owner")
	h.assigned(userID)
	h.orgs.EXPECT().FindByID(gomock.Any(), gomock.Any()).Times(0)

	ctx := types.WithPrincipal(context.Background(), types.Principal{UserID: userID, OrganizationID: orgID})
	holding, authErr := h.access.Holding(ctx, userID, access.OrgScope(orgID))
	s.Nil(authErr)
	s.Equal([]string{"owner"}, holding.RoleKeys())
}

func (s *AccessServiceSuite) TestHolding_ScopeMustBeAvailable() {
	h := newHarness(&s.Suite)
	_, authErr := h.access.Holding(context.Background(), userID, access.OrgScope(""))
	s.NotNil(authErr)
	s.Equal(types.ErrRBACScopeUnavailable, authErr.Code)

	_, authErr = h.access.Holding(context.Background(), userID, access.Scope{Type: "team", ID: "t"})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACScopeUnavailable, authErr.Code)

	_, authErr = h.access.Holding(context.Background(), userID, access.Scope{Type: access.ScopeGlobal, ID: "x"})
	s.NotNil(authErr)

	off := newHarness(&s.Suite, func(settings *services.Settings) { settings.Organizations = false })
	_, authErr = off.access.Holding(context.Background(), userID, access.OrgScope(orgID))
	s.NotNil(authErr)
	s.Equal(types.ErrRBACScopeUnavailable, authErr.Code)
}

func (s *AccessServiceSuite) TestHolding_StorageFailureIsAnErrorNotADenial() {
	h := newHarness(&s.Suite)
	h.users.EXPECT().FindByID(gomock.Any(), userID).Return(nil, errors.New("db down"))
	_, authErr := h.access.Holding(context.Background(), userID, access.GlobalScope())
	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)

	h = newHarness(&s.Suite)
	h.user(userID)
	h.assignments.EXPECT().ListByUser(gomock.Any(), userID, gomock.Any()).Return(nil, errors.New("db down"))
	_, authErr = h.access.Holding(context.Background(), userID, access.GlobalScope())
	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)

	h = newHarness(&s.Suite)
	h.user(userID)
	h.members.EXPECT().FindByOrgAndUser(gomock.Any(), orgID, userID).Return(nil, errors.New("db down"))
	_, authErr = h.access.Holding(context.Background(), userID, access.OrgScope(orgID))
	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

func (s *AccessServiceSuite) TestHolding_IsRememberedWithinARequestOnly() {
	h := newHarness(&s.Suite)
	h.users.EXPECT().FindByID(gomock.Any(), userID).Return(&models.User{ID: userID, Active: true}, nil).Times(3)
	h.assignments.EXPECT().ListByUser(gomock.Any(), userID, gomock.Any()).Return(nil, nil).Times(3)

	request := services.WithMemo(context.Background())
	s.Equal(request, services.WithMemo(request), "a context keeps its memo")
	for range 3 {
		_, authErr := h.access.Holding(request, userID, access.GlobalScope())
		s.Nil(authErr)
	}
	services.ResetMemo(request)
	_, authErr := h.access.Holding(request, userID, access.GlobalScope())
	s.Nil(authErr, "after a reset the roles are read again")

	_, authErr = h.access.Holding(context.Background(), userID, access.GlobalScope())
	s.Nil(authErr, "without a memo every call reads")
}

// --- Authorize ---

func (s *AccessServiceSuite) authorize(h *harness, permission string, mutate ...func(*services.AuthorizeRequest)) *services.Verdict {
	req := services.AuthorizeRequest{UserID: userID, Permission: permission, Scope: access.GlobalScope()}
	for _, fn := range mutate {
		fn(&req)
	}
	verdict, authErr := h.access.Authorize(context.Background(), req)
	s.Require().Nil(authErr)
	return verdict
}

func (s *AccessServiceSuite) TestAuthorize_RolesDecide() {
	h := newHarness(&s.Suite)
	h.user(userID)
	h.assigned(userID, globalRow(userID, "viewer"))

	allowed := s.authorize(h, "invoice:read")
	s.True(allowed.Allowed)
	s.True(allowed.Check.Granted)
	s.Equal([]string{"viewer"}, allowed.Check.Roles)
	s.Equal(access.ScopeGlobal, allowed.Check.Scope)

	denied := s.authorize(h, "invoice:approve")
	s.False(denied.Allowed)
	s.False(denied.Check.Granted)
	s.Equal("Missing permission: invoice:approve", services.DeniedError(denied.Check).Message)
}

func (s *AccessServiceSuite) TestAuthorize_ConditionsAdjustTheDecision() {
	h := newHarness(&s.Suite)
	h.user(userID)
	h.assigned(userID, globalRow(userID, "viewer"))
	yes := func(context.Context, access.Check) bool { return true }
	no := func(context.Context, access.Check) bool { return false }
	boom := func(context.Context, access.Check) bool { panic("boom") }

	s.True(s.authorize(h, "invoice:approve", func(r *services.AuthorizeRequest) { r.AllowIf = []access.Condition{no, yes} }).Allowed)
	s.False(s.authorize(h, "invoice:approve", func(r *services.AuthorizeRequest) { r.AllowIf = []access.Condition{no} }).Allowed)
	s.False(s.authorize(h, "invoice:read", func(r *services.AuthorizeRequest) { r.OnlyIf = []access.Condition{yes, no} }).Allowed)
	s.True(s.authorize(h, "invoice:read", func(r *services.AuthorizeRequest) { r.OnlyIf = []access.Condition{yes} }).Allowed)

	// OnlyIf still applies to a request AllowIf let through.
	s.False(s.authorize(h, "invoice:approve", func(r *services.AuthorizeRequest) {
		r.AllowIf = []access.Condition{yes}
		r.OnlyIf = []access.Condition{no}
	}).Allowed)

	// A condition that panics, or is nil, counts as false either way.
	s.False(s.authorize(h, "invoice:approve", func(r *services.AuthorizeRequest) { r.AllowIf = []access.Condition{boom} }).Allowed)
	s.False(s.authorize(h, "invoice:read", func(r *services.AuthorizeRequest) { r.OnlyIf = []access.Condition{boom} }).Allowed)
	s.False(s.authorize(h, "invoice:approve", func(r *services.AuthorizeRequest) { r.AllowIf = []access.Condition{nil} }).Allowed)
	s.False(s.authorize(h, "invoice:read", func(r *services.AuthorizeRequest) { r.OnlyIf = []access.Condition{nil} }).Allowed)
}

func (s *AccessServiceSuite) TestAuthorize_DecideHasTheLastWord() {
	var seen []access.Check
	h := newHarness(&s.Suite, func(settings *services.Settings) {
		settings.Decide = func(_ context.Context, c access.Check) access.Decision {
			seen = append(seen, c)
			switch c.Permission {
			case "report:export":
				return access.Deny("Exports need the Pro plan")
			case "beta:use":
				return access.Allow()
			case "crash:now":
				panic("boom")
			}
			return access.Keep
		}
	})
	h.user(userID)
	h.assigned(userID, globalRow(userID, "viewer"))

	s.True(s.authorize(h, "invoice:read").Allowed, "Keep leaves an allowed request allowed")
	s.False(s.authorize(h, "invoice:approve").Allowed, "Keep leaves a refused request refused")

	denied := s.authorize(h, "report:export", func(r *services.AuthorizeRequest) {
		r.AllowIf = []access.Condition{func(context.Context, access.Check) bool { return true }}
	})
	s.False(denied.Allowed)
	s.Equal("Exports need the Pro plan", denied.Check.Reason)
	s.Equal("Exports need the Pro plan", services.DeniedError(denied.Check).Message)
	last := seen[len(seen)-1]
	s.False(last.Granted, "Decide sees what the roles said")
	s.True(last.Allowed, "and what the conditions made of it")

	s.True(s.authorize(h, "beta:use").Allowed, "Allow overrules the roles")
	s.False(s.authorize(h, "crash:now").Allowed, "a Decide that panics denies")
}

func (s *AccessServiceSuite) TestAuthorize_MalformedPermissionIsAnError() {
	h := newHarness(&s.Suite)
	for _, permission := range []string{"", "invoice", "Invoice:read", "invoice:*", "*"} {
		_, authErr := h.access.Authorize(context.Background(), services.AuthorizeRequest{UserID: userID, Permission: permission, Scope: access.GlobalScope()})
		s.NotNil(authErr, permission)
		s.Equal(types.ErrInternalError, authErr.Code, permission)
	}
}
