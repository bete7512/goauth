package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/organization/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/organization/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

// ============= Member Service Tests =============

type MemberServiceSuite struct {
	suite.Suite
}

func TestMemberServiceSuite(t *testing.T) {
	suite.Run(t, new(MemberServiceSuite))
}

type memberTestSetup struct {
	svc        services.MemberService
	memberRepo *mocks.MockOrganizationMemberRepository
	orgRepo    *mocks.MockOrganizationRepository
	userRepo   *mocks.MockUserRepository
	events     *mocks.MockEventBus
}

func (s *MemberServiceSuite) setup() *memberTestSetup {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	memberRepo := mocks.NewMockOrganizationMemberRepository(ctrl)
	orgRepo := mocks.NewMockOrganizationRepository(ctrl)
	userRepo := mocks.NewMockUserRepository(ctrl)
	events := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)
	mockLogger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(), Events: events, Logger: mockLogger,
		SecurityManager: testutil.TestSecurityManager(), AuthInterceptors: interceptor.NewRegistry(),
	}
	svc := services.NewMemberService(deps, memberRepo, orgRepo, userRepo, 100)
	return &memberTestSetup{svc: svc, memberRepo: memberRepo, orgRepo: orgRepo, userRepo: userRepo, events: events}
}

func (s *MemberServiceSuite) TestListMembers_Success() {
	t := s.setup()
	user := testutil.TestUser()
	members := []*models.OrganizationMember{{UserID: user.ID, Role: "admin"}}

	t.memberRepo.EXPECT().ListByOrg(gomock.Any(), "org-1", gomock.Any()).Return(members, int64(1), nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)

	result, total, authErr := t.svc.ListMembers(context.Background(), "org-1", models.MemberListOpts{})
	s.Nil(authErr)
	s.Equal(int64(1), total)
	s.Len(result, 1)
	s.Empty(result[0].User.PasswordHash, "password should be cleared")
}

func (s *MemberServiceSuite) TestListMembers_Error() {
	t := s.setup()
	t.memberRepo.EXPECT().ListByOrg(gomock.Any(), "org-1", gomock.Any()).Return(nil, int64(0), errors.New("db"))

	_, _, authErr := t.svc.ListMembers(context.Background(), "org-1", models.MemberListOpts{})
	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

func (s *MemberServiceSuite) TestGetMember_Success() {
	t := s.setup()
	user := testutil.TestUser()
	member := &models.OrganizationMember{OrgID: "org-1", UserID: user.ID, Role: "member"}

	t.memberRepo.EXPECT().FindByOrgAndUser(gomock.Any(), "org-1", user.ID).Return(member, nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)

	result, authErr := t.svc.GetMember(context.Background(), "org-1", user.ID)
	s.Nil(authErr)
	s.NotNil(result.User)
}

func (s *MemberServiceSuite) TestGetMember_NotFound() {
	t := s.setup()
	t.memberRepo.EXPECT().FindByOrgAndUser(gomock.Any(), "org-1", "unknown").Return(nil, models.ErrNotFound)

	_, authErr := t.svc.GetMember(context.Background(), "org-1", "unknown")
	s.NotNil(authErr)
	s.Equal(types.ErrOrgMemberNotFound, authErr.Code)
}

func (s *MemberServiceSuite) TestUpdateRole_Success() {
	t := s.setup()
	org := &models.Organization{ID: "org-1", OwnerID: "owner-1", Name: "Team"}
	member := &models.OrganizationMember{OrgID: "org-1", UserID: "user-2", Role: "member"}

	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)
	t.memberRepo.EXPECT().FindByOrgAndUser(gomock.Any(), "org-1", "user-2").Return(member, nil)
	t.memberRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgMemberRoleChanged, gomock.Any()).Return(nil)

	authErr := t.svc.UpdateRole(context.Background(), "org-1", "user-2", types.OrgRoleAdmin, "owner-1")
	s.Nil(authErr)
}

func (s *MemberServiceSuite) TestUpdateRole_CannotChangeOwner() {
	t := s.setup()
	org := &models.Organization{ID: "org-1", OwnerID: "owner-1"}

	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)

	authErr := t.svc.UpdateRole(context.Background(), "org-1", "owner-1", types.OrgRoleMember, "admin-1")
	s.NotNil(authErr)
	s.Equal(types.ErrOrgCannotRemoveOwner, authErr.Code)
}

func (s *MemberServiceSuite) TestRemoveMember_Success() {
	t := s.setup()
	org := &models.Organization{ID: "org-1", OwnerID: "owner-1", Name: "Team"}
	member := &models.OrganizationMember{OrgID: "org-1", UserID: "user-2"}

	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)
	t.memberRepo.EXPECT().FindByOrgAndUser(gomock.Any(), "org-1", "user-2").Return(member, nil)
	t.memberRepo.EXPECT().DeleteByOrgAndUser(gomock.Any(), "org-1", "user-2").Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgMemberRemoved, gomock.Any()).Return(nil)

	authErr := t.svc.RemoveMember(context.Background(), "org-1", "user-2", "owner-1")
	s.Nil(authErr)
}

func (s *MemberServiceSuite) TestRemoveMember_CannotRemoveOwner() {
	t := s.setup()
	org := &models.Organization{ID: "org-1", OwnerID: "owner-1"}

	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)

	authErr := t.svc.RemoveMember(context.Background(), "org-1", "owner-1", "admin-1")
	s.NotNil(authErr)
	s.Equal(types.ErrOrgCannotRemoveOwner, authErr.Code)
}

// ============= Invitation Service Tests =============

type InvitationServiceSuite struct {
	suite.Suite
}

func TestInvitationServiceSuite(t *testing.T) {
	suite.Run(t, new(InvitationServiceSuite))
}

type inviteTestSetup struct {
	svc            services.InvitationService
	invitationRepo *mocks.MockOrgInvitationRepository
	memberRepo     *mocks.MockOrganizationMemberRepository
	orgRepo        *mocks.MockOrganizationRepository
	userRepo       *mocks.MockUserRepository
	events         *mocks.MockEventBus
}

func (s *InvitationServiceSuite) setup() *inviteTestSetup {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	invitationRepo := mocks.NewMockOrgInvitationRepository(ctrl)
	memberRepo := mocks.NewMockOrganizationMemberRepository(ctrl)
	orgRepo := mocks.NewMockOrganizationRepository(ctrl)
	userRepo := mocks.NewMockUserRepository(ctrl)
	events := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)
	mockLogger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(), Events: events, Logger: mockLogger,
		SecurityManager: testutil.TestSecurityManager(), AuthInterceptors: interceptor.NewRegistry(),
	}
	svc := services.NewInvitationService(deps, invitationRepo, memberRepo, orgRepo, userRepo, 7*24*time.Hour, "https://example.com/invite", 100)
	return &inviteTestSetup{svc: svc, invitationRepo: invitationRepo, memberRepo: memberRepo, orgRepo: orgRepo, userRepo: userRepo, events: events}
}

func (s *InvitationServiceSuite) TestInvite_Success() {
	t := s.setup()
	org := &models.Organization{ID: "org-1", Name: "Team"}

	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, models.ErrNotFound)
	t.invitationRepo.EXPECT().FindByOrgAndEmail(gomock.Any(), "org-1", "new@example.com").Return(nil, models.ErrNotFound)
	t.memberRepo.EXPECT().CountByOrg(gomock.Any(), "org-1").Return(int64(5), nil) // under limit
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), "inviter-1").Return(testutil.TestUser(), nil)
	t.invitationRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.OrgInvitation{})).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgInvitationSent, gomock.Any()).Return(nil)

	inv, authErr := t.svc.Invite(context.Background(), "org-1", &dto.InviteRequest{Email: "new@example.com"}, "inviter-1")
	s.Nil(authErr)
	s.NotNil(inv)
	s.Equal("new@example.com", inv.Email)
	s.Equal(string(types.OrgRoleMember), inv.Role) // default role
}

func (s *InvitationServiceSuite) TestInvite_AlreadyMember() {
	t := s.setup()
	user := testutil.TestUser()
	user.Email = "existing@example.com"
	member := &models.OrganizationMember{UserID: user.ID}

	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "existing@example.com").Return(user, nil)
	t.memberRepo.EXPECT().FindByOrgAndUser(gomock.Any(), "org-1", user.ID).Return(member, nil)

	_, authErr := t.svc.Invite(context.Background(), "org-1", &dto.InviteRequest{Email: "existing@example.com"}, "inviter-1")
	s.NotNil(authErr)
	s.Equal(types.ErrOrgMemberExists, authErr.Code)
}

func (s *InvitationServiceSuite) TestInvite_DuplicatePending() {
	t := s.setup()
	existingInv := &models.OrgInvitation{Email: "pending@example.com", Status: models.InvitationStatusPending}

	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "pending@example.com").Return(nil, models.ErrNotFound)
	t.invitationRepo.EXPECT().FindByOrgAndEmail(gomock.Any(), "org-1", "pending@example.com").Return(existingInv, nil)

	_, authErr := t.svc.Invite(context.Background(), "org-1", &dto.InviteRequest{Email: "pending@example.com"}, "inviter-1")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationExists, authErr.Code)
}

func (s *InvitationServiceSuite) TestAcceptInvitation_ExistingUser() {
	t := s.setup()
	inv := &models.OrgInvitation{
		ID: "inv-1", OrgID: "org-1", Email: "user@example.com", Role: "member",
		Token: "valid-token", Status: models.InvitationStatusPending,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	existingUser := testutil.TestUser()
	existingUser.Email = "user@example.com"
	org := &models.Organization{ID: "org-1", Name: "Team"}

	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "valid-token").Return(inv, nil)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "user@example.com").Return(existingUser, nil)
	t.memberRepo.EXPECT().FindByOrgAndUser(gomock.Any(), "org-1", existingUser.ID).Return(nil, models.ErrNotFound)
	t.memberRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.OrganizationMember{})).Return(nil)
	t.invitationRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgInvitationAccepted, gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgMemberAdded, gomock.Any()).Return(nil)

	result, authErr := t.svc.AcceptInvitation(context.Background(), "valid-token", "", "")
	s.Nil(authErr)
	s.NotNil(result)
	s.False(result.IsNewUser)
	s.Equal(existingUser.ID, result.Member.UserID)
}

func (s *InvitationServiceSuite) TestAcceptInvitation_NewUser() {
	t := s.setup()
	inv := &models.OrgInvitation{
		ID: "inv-1", OrgID: "org-1", Email: "new@example.com", Role: "member",
		Token: "valid-token", Status: models.InvitationStatusPending,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	org := &models.Organization{ID: "org-1", Name: "Team"}

	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "valid-token").Return(inv, nil)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
	t.memberRepo.EXPECT().FindByOrgAndUser(gomock.Any(), "org-1", gomock.Any()).Return(nil, models.ErrNotFound)
	t.memberRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.OrganizationMember{})).Return(nil)
	t.invitationRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgInvitationAccepted, gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgMemberAdded, gomock.Any()).Return(nil)

	result, authErr := t.svc.AcceptInvitation(context.Background(), "valid-token", "New User", "password123")
	s.Nil(authErr)
	s.NotNil(result)
	s.True(result.IsNewUser)
}

func (s *InvitationServiceSuite) TestAcceptInvitation_Expired() {
	t := s.setup()
	inv := &models.OrgInvitation{
		Token: "expired-token", Status: models.InvitationStatusPending,
		Email: "user@example.com", ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "expired-token").Return(inv, nil)

	_, authErr := t.svc.AcceptInvitation(context.Background(), "expired-token", "", "")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationExpired, authErr.Code)
}

func (s *InvitationServiceSuite) TestDeclineInvitation_Success() {
	t := s.setup()
	inv := &models.OrgInvitation{Token: "tok", Status: models.InvitationStatusPending, OrgID: "org-1", Email: "user@example.com"}

	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "tok").Return(inv, nil)
	t.invitationRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgInvitationDeclined, gomock.Any()).Return(nil)

	authErr := t.svc.DeclineInvitation(context.Background(), "tok")
	s.Nil(authErr)
}

func (s *InvitationServiceSuite) TestDeclineInvitation_NotFound() {
	t := s.setup()
	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "bad-tok").Return(nil, models.ErrNotFound)

	authErr := t.svc.DeclineInvitation(context.Background(), "bad-tok")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationNotFound, authErr.Code)
}

func (s *InvitationServiceSuite) TestCancelInvitation_Success() {
	t := s.setup()
	inv := &models.OrgInvitation{ID: "inv-1", OrgID: "org-1"}
	t.invitationRepo.EXPECT().FindByID(gomock.Any(), "inv-1").Return(inv, nil)
	t.invitationRepo.EXPECT().Delete(gomock.Any(), "inv-1").Return(nil)

	authErr := t.svc.CancelInvitation(context.Background(), "org-1", "inv-1")
	s.Nil(authErr)
}

func (s *InvitationServiceSuite) TestCancelInvitation_NotFound() {
	t := s.setup()
	t.invitationRepo.EXPECT().FindByID(gomock.Any(), "inv-999").Return(nil, models.ErrNotFound)

	authErr := t.svc.CancelInvitation(context.Background(), "org-1", "inv-999")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationNotFound, authErr.Code)
}

func (s *InvitationServiceSuite) TestListPendingByEmail_Success() {
	t := s.setup()
	invitations := []*models.OrgInvitation{{Email: "user@example.com"}}
	t.invitationRepo.EXPECT().ListPendingByEmail(gomock.Any(), "user@example.com").Return(invitations, nil)

	result, authErr := t.svc.ListPendingByEmail(context.Background(), "user@example.com")
	s.Nil(authErr)
	s.Len(result, 1)
}
