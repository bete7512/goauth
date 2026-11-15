package services_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type AssignmentServiceSuite struct {
	suite.Suite
}

func TestAssignmentServiceSuite(t *testing.T) {
	suite.Run(t, new(AssignmentServiceSuite))
}

const targetMembership = "membership-2"

// ownerAndTarget makes userID the organization's owner and otherUser a plain
// member holding the given assignment rows.
func ownerAndTarget(h *harness, rows ...*models.RoleAssignment) {
	owner(h)
	h.user(otherUser)
	h.member(otherUser, targetMembership, "member")
	h.assigned(otherUser, rows...)
}

func (s *AssignmentServiceSuite) TestSet_AddsAndRemovesTheDifference() {
	h := newHarness(&s.Suite)
	ownerAndTarget(h, orgRow(otherUser, "billing", targetMembership), orgRow(otherUser, "auditor", targetMembership))
	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "billing").Return(storedRole(orgID, "billing", "invoice:*"), nil).AnyTimes()
	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "auditor").Return(storedRole(orgID, "auditor", "audit:read"), nil).AnyTimes()
	h.roles.EXPECT().FindByKeys(gomock.Any(), orgID, gomock.Any()).Return(nil, nil).AnyTimes()

	gomock.InOrder(
		h.events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeRBACRoleAssign, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ types.EventType, data interface{}) error {
				event := data.(*types.RBACAssignmentEventData)
				s.Equal("viewer", event.RoleKey)
				s.Equal(otherUser, event.UserID)
				s.Equal(models.RoleScopeOrg, event.ScopeType)
				s.Equal(orgID, event.ScopeID)
				s.Equal(userID, event.ActorID)
				return nil
			}),
		h.assignments.EXPECT().Delete(gomock.Any(), otherUser, models.RoleScopeOrg, orgID, "auditor").Return(nil),
		h.assignments.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, row *models.RoleAssignment) error {
				s.Equal("viewer", row.RoleKey)
				s.Equal(targetMembership, row.MembershipID, "the assignment is tied to the membership it was made for")
				s.Equal(userID, row.GrantedBy)
				return nil
			}),
		h.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleRevoked, gomock.Any()).Return(nil),
		h.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleAssigned, gomock.Any()).Return(nil),
	)

	_, authErr := h.assign.Set(context.Background(), actor(userID), otherUser, access.OrgScope(orgID), []string{"billing", " viewer ", "billing"})
	s.Nil(authErr)
}

func (s *AssignmentServiceSuite) TestSet_Refusals() {
	scope := access.OrgScope(orgID)

	h := newHarness(&s.Suite)
	ownerAndTarget(h)
	for _, key := range []string{access.RoleOwner, access.RoleMember, access.RoleSuperAdmin} {
		_, authErr := h.assign.Set(context.Background(), actor(userID), otherUser, scope, []string{key})
		s.NotNil(authErr, key)
		s.Equal(types.ErrRBACRoleSystem, authErr.Code, key)
	}

	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "missing").Return(nil, models.ErrNotFound)
	_, authErr := h.assign.Set(context.Background(), actor(userID), otherUser, scope, []string{"missing"})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACRoleNotFound, authErr.Code)

	h.roles.EXPECT().FindByKey(gomock.Any(), orgID, gomock.Any()).DoAndReturn(
		func(_ context.Context, _, key string) (*models.Role, error) {
			return storedRole(orgID, key, "invoice:read"), nil
		}).Times(2)
	_, authErr = h.assign.Set(context.Background(), actor(userID), otherUser, scope, []string{"viewer", "a", "b"})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACLimitExceeded, authErr.Code, "at most two roles per user in this harness")

	// The target must be a member of the organization.
	h = newHarness(&s.Suite)
	owner(h)
	h.notMember(otherUser)
	_, authErr = h.assign.Set(context.Background(), actor(userID), otherUser, scope, []string{"viewer"})
	s.NotNil(authErr)
	s.Equal(types.ErrOrgMemberNotFound, authErr.Code)

	// The caller needs the permission: an admin does not have it.
	h = newHarness(&s.Suite)
	h.user(userID)
	h.org(true)
	h.member(userID, memberID, "admin")
	h.assigned(userID)
	_, authErr = h.assign.Set(context.Background(), actor(userID), otherUser, scope, []string{"viewer"})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACPermissionDenied, authErr.Code)
}

func (s *AssignmentServiceSuite) TestSet_CallerMustHoldWhatIsGivenAndTaken() {
	delegate := func(target ...*models.RoleAssignment) *harness {
		h := newHarness(&s.Suite)
		h.user(userID)
		h.org(true)
		h.member(userID, memberID, "member")
		h.assigned(userID, orgRow(userID, "delegate", memberID))
		h.user(otherUser)
		h.member(otherUser, targetMembership, "member")
		h.assigned(otherUser, target...)
		h.roles.EXPECT().FindByKeys(gomock.Any(), orgID, []string{"delegate"}).
			Return([]*models.Role{storedRole(orgID, "delegate", "goauth.assignments:*", "invoice:read")}, nil).AnyTimes()
		h.roles.EXPECT().FindByKey(gomock.Any(), orgID, "approver").Return(storedRole(orgID, "approver", "invoice:approve"), nil).AnyTimes()
		return h
	}

	h := delegate()
	_, authErr := h.assign.Set(context.Background(), actor(userID), otherUser, access.OrgScope(orgID), []string{"approver"})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACGrantNotHeld, authErr.Code, "giving")

	h = delegate(orgRow(otherUser, "approver", targetMembership))
	_, authErr = h.assign.Set(context.Background(), actor(userID), otherUser, access.OrgScope(orgID), []string{})
	s.NotNil(authErr)
	s.Equal(types.ErrRBACGrantNotHeld, authErr.Code, "taking away")
}

func (s *AssignmentServiceSuite) TestSet_SubscriberRefusal() {
	refusal := func(err error) *types.GoAuthError {
		h := newHarness(&s.Suite)
		ownerAndTarget(h)
		h.events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeRBACRoleAssign, gomock.Any()).Return(err)
		_, authErr := h.assign.Set(context.Background(), actor(userID), otherUser, access.OrgScope(orgID), []string{"viewer"})
		s.Require().NotNil(authErr)
		return authErr
	}

	wrapped := refusal(fmt.Errorf("event bus: handler error: %w", errors.New("your plan allows 3 admins")))
	s.Equal(types.ErrRBACAssignmentRefused, wrapped.Code)
	s.Equal("your plan allows 3 admins", wrapped.Message, "the subscriber's own words reach the caller")

	typed := refusal(fmt.Errorf("event bus: handler error: %w", types.NewForbiddenError()))
	s.Equal(types.ErrForbidden, typed.Code, "a typed error is passed through")

	statusless := refusal(fmt.Errorf("event bus: handler error: %w", types.NewCustomError("seat limit reached")))
	s.Equal(types.ErrCustom, statusless.Code)
	s.Equal("seat limit reached", statusless.Message)
	s.Equal(403, statusless.StatusCode, "a typed error without a status is answered as a refusal")
}

// Rows left behind by an earlier membership are deleted, not kept as if the
// user still held them.
func (s *AssignmentServiceSuite) TestSet_ReplacesRowsOfAnEarlierMembership() {
	h := newHarness(&s.Suite)
	ownerAndTarget(h, orgRow(otherUser, "viewer", "membership-old"))
	h.roles.EXPECT().FindByKeys(gomock.Any(), orgID, gomock.Any()).Return(nil, nil).AnyTimes()
	gomock.InOrder(
		h.assignments.EXPECT().Delete(gomock.Any(), otherUser, models.RoleScopeOrg, orgID, "viewer").Return(nil),
		h.events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeRBACRoleAssign, gomock.Any()).Return(nil),
		h.assignments.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, row *models.RoleAssignment) error {
				s.Equal(targetMembership, row.MembershipID)
				return nil
			}),
		h.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleAssigned, gomock.Any()).Return(nil),
	)
	_, authErr := h.assign.Set(context.Background(), actor(userID), otherUser, access.OrgScope(orgID), []string{"viewer"})
	s.Nil(authErr)
}

func (s *AssignmentServiceSuite) TestAssign_GlobalFromTrustedCode() {
	h := newHarness(&s.Suite)
	h.user(otherUser)
	h.assigned(otherUser)
	gomock.InOrder(
		h.events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeRBACRoleAssign, gomock.Any()).Return(nil),
		h.assignments.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, row *models.RoleAssignment) error {
				s.Equal(models.RoleScopeGlobal, row.ScopeType)
				s.Empty(row.ScopeID)
				s.Empty(row.MembershipID)
				s.Empty(row.GrantedBy)
				return nil
			}),
		h.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleAssigned, gomock.Any()).Return(nil),
	)
	s.Nil(h.assign.Assign(context.Background(), nil, otherUser, access.GlobalScope(), "viewer"))
}

func (s *AssignmentServiceSuite) TestAssign_IsIdempotentAndBounded() {
	h := newHarness(&s.Suite)
	h.user(otherUser)
	h.assigned(otherUser, globalRow(otherUser, "viewer"))
	s.Nil(h.assign.Assign(context.Background(), nil, otherUser, access.GlobalScope(), "viewer"), "already held: nothing is written")

	// A concurrent request created the row first.
	h = newHarness(&s.Suite)
	h.user(otherUser)
	h.assigned(otherUser)
	h.events.EXPECT().EmitSync(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	h.assignments.EXPECT().Create(gomock.Any(), gomock.Any()).Return(models.ErrConflict)
	h.events.EXPECT().EmitAsync(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	s.Nil(h.assign.Assign(context.Background(), nil, otherUser, access.GlobalScope(), "viewer"))

	h = newHarness(&s.Suite)
	h.user(otherUser)
	h.assigned(otherUser, globalRow(otherUser, "a"), globalRow(otherUser, "b"))
	authErr := h.assign.Assign(context.Background(), nil, otherUser, access.GlobalScope(), "viewer")
	s.NotNil(authErr)
	s.Equal(types.ErrRBACLimitExceeded, authErr.Code)

	h = newHarness(&s.Suite)
	h.noUser(otherUser)
	authErr = h.assign.Assign(context.Background(), nil, otherUser, access.GlobalScope(), "viewer")
	s.NotNil(authErr)
	s.Equal(types.ErrUserNotFound, authErr.Code)

	authErr = h.assign.Assign(context.Background(), nil, "", access.GlobalScope(), "viewer")
	s.NotNil(authErr)
	s.Equal(types.ErrUserNotFound, authErr.Code)
}

func (s *AssignmentServiceSuite) TestRevoke() {
	h := newHarness(&s.Suite)
	h.assigned(otherUser, globalRow(otherUser, "viewer"))
	gomock.InOrder(
		h.assignments.EXPECT().Delete(gomock.Any(), otherUser, models.RoleScopeGlobal, "", "viewer").Return(nil),
		h.events.EXPECT().EmitAsync(gomock.Any(), types.EventRBACRoleRevoked, gomock.Any()).Return(nil),
	)
	s.Nil(h.assign.Revoke(context.Background(), nil, otherUser, access.GlobalScope(), "viewer"))

	h = newHarness(&s.Suite)
	h.assigned(otherUser)
	s.Nil(h.assign.Revoke(context.Background(), nil, otherUser, access.GlobalScope(), "viewer"), "not held: nothing is written")

	authErr := h.assign.Revoke(context.Background(), nil, otherUser, access.GlobalScope(), access.RoleSuperAdmin)
	s.NotNil(authErr)
	s.Equal(types.ErrRBACRoleSystem, authErr.Code)
}

func (s *AssignmentServiceSuite) TestGet_OwnRolesNeedNoPermission() {
	h := newHarness(&s.Suite)
	h.user(userID)
	h.member(userID, memberID, "member")
	h.org(true)
	h.assigned(userID, orgRow(userID, "viewer", memberID))

	roles, authErr := h.assign.Get(context.Background(), actor(userID), userID, access.OrgScope(orgID))
	s.Nil(authErr)
	s.Equal([]string{"*:read"}, roles.Grants)
	s.Len(roles.Roles, 2)

	// Reading someone else's needs the permission, which a member lacks.
	_, authErr = h.assign.Get(context.Background(), actor(userID), otherUser, access.OrgScope(orgID))
	s.NotNil(authErr)
	s.Equal(types.ErrRBACPermissionDenied, authErr.Code)
}

func (s *AssignmentServiceSuite) TestList() {
	h := newHarness(&s.Suite)
	owner(h)
	rows := []*models.RoleAssignment{orgRow(otherUser, "viewer", targetMembership)}
	opts := models.RoleAssignmentListOpts{RoleKey: "viewer"}
	h.assignments.EXPECT().ListByScope(gomock.Any(), models.RoleScopeOrg, orgID, opts).Return(rows, int64(1), nil)

	got, total, authErr := h.assign.List(context.Background(), actor(userID), access.OrgScope(orgID), opts)
	s.Nil(authErr)
	s.EqualValues(1, total)
	s.Equal(rows, got)
}

func (s *AssignmentServiceSuite) TestCleanup() {
	h := newHarness(&s.Suite)
	h.assignments.EXPECT().DeleteByUser(gomock.Any(), otherUser).Return(nil)
	h.assignments.EXPECT().DeleteByUserAndScope(gomock.Any(), otherUser, models.RoleScopeOrg, orgID).Return(nil)
	s.NoError(h.assign.RemoveUser(context.Background(), otherUser))
	s.NoError(h.assign.RemoveMember(context.Background(), orgID, otherUser))
	s.NoError(h.assign.RemoveUser(context.Background(), ""), "an empty ID deletes nothing")
	s.NoError(h.assign.RemoveMember(context.Background(), "", otherUser))
}
