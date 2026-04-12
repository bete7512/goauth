package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/invitation/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/invitation/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type InvitationServiceSuite struct {
	suite.Suite
}

func TestInvitationServiceSuite(t *testing.T) {
	suite.Run(t, new(InvitationServiceSuite))
}

type testSetup struct {
	svc            services.InvitationService
	invitationRepo *mocks.MockInvitationRepository
	userRepo       *mocks.MockUserRepository
	events         *mocks.MockEventBus
}

func (s *InvitationServiceSuite) setup() *testSetup {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	invitationRepo := mocks.NewMockInvitationRepository(ctrl)
	userRepo := mocks.NewMockUserRepository(ctrl)
	events := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)
	mockLogger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(), Events: events, Logger: mockLogger,
		SecurityManager: testutil.TestSecurityManager(), AuthInterceptors: interceptor.NewRegistry(),
	}
	svc := services.NewInvitationService(deps, invitationRepo, userRepo, 7*24*time.Hour, "https://example.com/invite", "platform", nil, -1)
	return &testSetup{svc: svc, invitationRepo: invitationRepo, userRepo: userRepo, events: events}
}

func (s *InvitationServiceSuite) setupWithPurposes(purposes []string) *testSetup {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	invitationRepo := mocks.NewMockInvitationRepository(ctrl)
	userRepo := mocks.NewMockUserRepository(ctrl)
	events := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)
	mockLogger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(), Events: events, Logger: mockLogger,
		SecurityManager: testutil.TestSecurityManager(), AuthInterceptors: interceptor.NewRegistry(),
	}
	svc := services.NewInvitationService(deps, invitationRepo, userRepo, 7*24*time.Hour, "https://example.com/invite", "platform", purposes, -1)
	return &testSetup{svc: svc, invitationRepo: invitationRepo, userRepo: userRepo, events: events}
}

func (s *InvitationServiceSuite) TestSend_Success() {
	t := s.setup()

	t.invitationRepo.EXPECT().FindPendingByEmail(gomock.Any(), "new@example.com", "platform").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByID(gomock.Any(), "inviter-1").Return(testutil.TestUser(), nil)
	t.invitationRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Invitation{})).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventInvitationSent, gomock.Any()).Return(nil)

	inv, authErr := t.svc.Send(context.Background(), &dto.SendInvitationRequest{Email: "new@example.com"}, "inviter-1")
	s.Nil(authErr)
	s.NotNil(inv)
	s.Equal("new@example.com", inv.Email)
	s.Equal("platform", inv.Purpose)
}

func (s *InvitationServiceSuite) TestSend_WithPurpose() {
	t := s.setup()

	t.invitationRepo.EXPECT().FindPendingByEmail(gomock.Any(), "new@example.com", "beta").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByID(gomock.Any(), "inviter-1").Return(testutil.TestUser(), nil)
	t.invitationRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Invitation{})).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventInvitationSent, gomock.Any()).Return(nil)

	inv, authErr := t.svc.Send(context.Background(), &dto.SendInvitationRequest{Email: "new@example.com", Purpose: "beta"}, "inviter-1")
	s.Nil(authErr)
	s.Equal("beta", inv.Purpose)
}

func (s *InvitationServiceSuite) TestSend_DuplicatePending() {
	t := s.setup()
	existingInv := &models.Invitation{Email: "pending@example.com", Status: models.InvitationStatusPending}

	t.invitationRepo.EXPECT().FindPendingByEmail(gomock.Any(), "pending@example.com", "platform").Return(existingInv, nil)

	_, authErr := t.svc.Send(context.Background(), &dto.SendInvitationRequest{Email: "pending@example.com"}, "inviter-1")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationExists, authErr.Code)
}

func (s *InvitationServiceSuite) TestSend_InvalidPurpose() {
	t := s.setupWithPurposes([]string{"platform", "beta"})

	_, authErr := t.svc.Send(context.Background(), &dto.SendInvitationRequest{Email: "new@example.com", Purpose: "unknown"}, "inviter-1")
	s.NotNil(authErr)
	s.Equal(types.ErrInvalidRequestBody, authErr.Code)
}

func (s *InvitationServiceSuite) TestAccept_ExistingUser() {
	t := s.setup()
	inv := &models.Invitation{
		ID: "inv-1", Email: "user@example.com", Purpose: "platform",
		Token: "valid-token", Status: models.InvitationStatusPending,
		InviterID: "inviter-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	existingUser := testutil.TestUser()
	existingUser.Email = "user@example.com"

	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "valid-token").Return(inv, nil)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "user@example.com").Return(existingUser, nil)
	t.invitationRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventInvitationAccepted, gomock.Any()).Return(nil)

	result, authErr := t.svc.Accept(context.Background(), "valid-token", "", "")
	s.Nil(authErr)
	s.NotNil(result)
	s.False(result.IsNewUser)
	s.Equal("user@example.com", result.User.Email)
}

func (s *InvitationServiceSuite) TestAccept_NewUser() {
	t := s.setup()
	inv := &models.Invitation{
		ID: "inv-1", Email: "new@example.com", Purpose: "platform",
		Token: "valid-token", Status: models.InvitationStatusPending,
		InviterID: "inviter-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "valid-token").Return(inv, nil)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
	t.invitationRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventInvitationAccepted, gomock.Any()).Return(nil)

	result, authErr := t.svc.Accept(context.Background(), "valid-token", "New User", "password123")
	s.Nil(authErr)
	s.NotNil(result)
	s.True(result.IsNewUser)
	s.Equal("new@example.com", result.User.Email)
}

func (s *InvitationServiceSuite) TestAccept_NewUserMissingPassword() {
	t := s.setup()
	inv := &models.Invitation{
		Token: "tok", Status: models.InvitationStatusPending,
		Email: "new@example.com", ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "tok").Return(inv, nil)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, models.ErrNotFound)

	_, authErr := t.svc.Accept(context.Background(), "tok", "", "")
	s.NotNil(authErr)
	s.Equal(types.ErrInvalidRequestBody, authErr.Code)
}

func (s *InvitationServiceSuite) TestAccept_Expired() {
	t := s.setup()
	inv := &models.Invitation{
		Token: "expired-token", Status: models.InvitationStatusPending,
		Email: "user@example.com", ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "expired-token").Return(inv, nil)

	_, authErr := t.svc.Accept(context.Background(), "expired-token", "", "")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationExpired, authErr.Code)
}

func (s *InvitationServiceSuite) TestAccept_AlreadyAccepted() {
	t := s.setup()
	inv := &models.Invitation{
		Token: "tok", Status: models.InvitationStatusAccepted,
		Email: "user@example.com", ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "tok").Return(inv, nil)

	_, authErr := t.svc.Accept(context.Background(), "tok", "", "")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationNotFound, authErr.Code)
}

func (s *InvitationServiceSuite) TestDecline_Success() {
	t := s.setup()
	inv := &models.Invitation{
		ID: "inv-1", Token: "tok", Status: models.InvitationStatusPending,
		Email: "user@example.com", Purpose: "platform",
	}

	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "tok").Return(inv, nil)
	t.invitationRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventInvitationDeclined, gomock.Any()).Return(nil)

	authErr := t.svc.Decline(context.Background(), "tok")
	s.Nil(authErr)
}

func (s *InvitationServiceSuite) TestDecline_NotFound() {
	t := s.setup()
	t.invitationRepo.EXPECT().FindByToken(gomock.Any(), "bad-tok").Return(nil, models.ErrNotFound)

	authErr := t.svc.Decline(context.Background(), "bad-tok")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationNotFound, authErr.Code)
}

func (s *InvitationServiceSuite) TestCancel_Success() {
	t := s.setup()
	inv := &models.Invitation{ID: "inv-1", InviterID: "inviter-1"}
	t.invitationRepo.EXPECT().FindByID(gomock.Any(), "inv-1").Return(inv, nil)
	t.invitationRepo.EXPECT().Delete(gomock.Any(), "inv-1").Return(nil)

	authErr := t.svc.Cancel(context.Background(), "inv-1", "inviter-1")
	s.Nil(authErr)
}

func (s *InvitationServiceSuite) TestCancel_NotInviter() {
	t := s.setup()
	inv := &models.Invitation{ID: "inv-1", InviterID: "inviter-1"}
	t.invitationRepo.EXPECT().FindByID(gomock.Any(), "inv-1").Return(inv, nil)

	authErr := t.svc.Cancel(context.Background(), "inv-1", "other-user")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationNotFound, authErr.Code)
}

func (s *InvitationServiceSuite) TestCancel_NotFound() {
	t := s.setup()
	t.invitationRepo.EXPECT().FindByID(gomock.Any(), "inv-999").Return(nil, models.ErrNotFound)

	authErr := t.svc.Cancel(context.Background(), "inv-999", "inviter-1")
	s.NotNil(authErr)
	s.Equal(types.ErrInvitationNotFound, authErr.Code)
}

func (s *InvitationServiceSuite) TestListPendingByEmail_Success() {
	t := s.setup()
	invitations := []*models.Invitation{{Email: "user@example.com"}}
	t.invitationRepo.EXPECT().ListPendingByEmail(gomock.Any(), "user@example.com").Return(invitations, nil)

	result, authErr := t.svc.ListPendingByEmail(context.Background(), "user@example.com")
	s.Nil(authErr)
	s.Len(result, 1)
}
