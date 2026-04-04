package services_test

import (
	"context"
	"errors"
	"testing"

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

type OrgServiceSuite struct {
	suite.Suite
}

func TestOrgServiceSuite(t *testing.T) {
	suite.Run(t, new(OrgServiceSuite))
}

type orgTestSetup struct {
	svc        services.OrgService
	orgRepo    *mocks.MockOrganizationRepository
	memberRepo *mocks.MockOrganizationMemberRepository
	userRepo   *mocks.MockUserRepository
	events     *mocks.MockEventBus
}

func (s *OrgServiceSuite) setup() *orgTestSetup {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	orgRepo := mocks.NewMockOrganizationRepository(ctrl)
	memberRepo := mocks.NewMockOrganizationMemberRepository(ctrl)
	userRepo := mocks.NewMockUserRepository(ctrl)
	events := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	// Allow any logger calls
	mockLogger.EXPECT().Info(gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	deps := config.ModuleDependencies{
		Config:           testutil.TestConfig(),
		Events:           events,
		Logger:           mockLogger,
		SecurityManager:  testutil.TestSecurityManager(),
		AuthInterceptors: interceptor.NewRegistry(),
	}

	svc := services.NewOrgService(deps, orgRepo, memberRepo, userRepo)

	return &orgTestSetup{
		svc: svc, orgRepo: orgRepo, memberRepo: memberRepo, userRepo: userRepo, events: events,
	}
}

// --- Create ---

func (s *OrgServiceSuite) TestCreate_Success() {
	t := s.setup()
	t.orgRepo.EXPECT().IsSlugAvailable(gomock.Any(), gomock.Any()).Return(true, nil)
	t.orgRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Organization{})).Return(nil)
	t.memberRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.OrganizationMember{})).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgCreated, gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgMemberAdded, gomock.Any()).Return(nil)

	org, authErr := t.svc.Create(context.Background(), "user-1", &dto.CreateOrgRequest{Name: "My Team"})

	s.Nil(authErr)
	s.NotNil(org)
	s.Equal("My Team", org.Name)
	s.Equal("user-1", org.OwnerID)
}

func (s *OrgServiceSuite) TestCreate_SlugTaken() {
	t := s.setup()
	t.orgRepo.EXPECT().IsSlugAvailable(gomock.Any(), gomock.Any()).Return(false, nil)

	_, authErr := t.svc.Create(context.Background(), "user-1", &dto.CreateOrgRequest{Name: "Taken Name"})

	s.NotNil(authErr)
	s.Equal(types.ErrOrgSlugTaken, authErr.Code)
}

func (s *OrgServiceSuite) TestCreate_RepoError() {
	t := s.setup()
	t.orgRepo.EXPECT().IsSlugAvailable(gomock.Any(), gomock.Any()).Return(true, nil)
	t.orgRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("db error"))

	_, authErr := t.svc.Create(context.Background(), "user-1", &dto.CreateOrgRequest{Name: "My Team"})

	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

// --- Get ---

func (s *OrgServiceSuite) TestGet_Success() {
	t := s.setup()
	org := &models.Organization{ID: "org-1", Name: "Team"}
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)

	result, authErr := t.svc.Get(context.Background(), "org-1")
	s.Nil(authErr)
	s.Equal("Team", result.Name)
}

func (s *OrgServiceSuite) TestGet_NotFound() {
	t := s.setup()
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-999").Return(nil, models.ErrNotFound)

	_, authErr := t.svc.Get(context.Background(), "org-999")
	s.NotNil(authErr)
	s.Equal(types.ErrOrgNotFound, authErr.Code)
}

// --- Update ---

func (s *OrgServiceSuite) TestUpdate_Success() {
	t := s.setup()
	org := &models.Organization{ID: "org-1", Name: "Old Name"}
	newName := "New Name"

	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)
	t.orgRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgUpdated, gomock.Any()).Return(nil)

	result, authErr := t.svc.Update(context.Background(), "org-1", &dto.UpdateOrgRequest{Name: &newName})
	s.Nil(authErr)
	s.Equal("New Name", result.Name)
}

func (s *OrgServiceSuite) TestUpdate_NotFound() {
	t := s.setup()
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-999").Return(nil, models.ErrNotFound)

	_, authErr := t.svc.Update(context.Background(), "org-999", &dto.UpdateOrgRequest{})
	s.NotNil(authErr)
	s.Equal(types.ErrOrgNotFound, authErr.Code)
}

// --- Delete ---

func (s *OrgServiceSuite) TestDelete_Success() {
	t := s.setup()
	org := &models.Organization{ID: "org-1", Name: "Team"}
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org, nil)
	t.orgRepo.EXPECT().Delete(gomock.Any(), "org-1").Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgDeleted, gomock.Any()).Return(nil)

	authErr := t.svc.Delete(context.Background(), "org-1")
	s.Nil(authErr)
}

func (s *OrgServiceSuite) TestDelete_NotFound() {
	t := s.setup()
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-999").Return(nil, models.ErrNotFound)

	authErr := t.svc.Delete(context.Background(), "org-999")
	s.NotNil(authErr)
	s.Equal(types.ErrOrgNotFound, authErr.Code)
}

// --- ListByUser ---

func (s *OrgServiceSuite) TestListByUser_Success() {
	t := s.setup()
	memberships := []*models.OrganizationMember{{OrgID: "org-1"}, {OrgID: "org-2"}}
	org1 := &models.Organization{ID: "org-1", Name: "Team 1"}
	org2 := &models.Organization{ID: "org-2", Name: "Team 2"}

	t.memberRepo.EXPECT().ListByUser(gomock.Any(), "user-1").Return(memberships, nil)
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-1").Return(org1, nil)
	t.orgRepo.EXPECT().FindByID(gomock.Any(), "org-2").Return(org2, nil)

	orgs, authErr := t.svc.ListByUser(context.Background(), "user-1")
	s.Nil(authErr)
	s.Len(orgs, 2)
}

func (s *OrgServiceSuite) TestListByUser_Empty() {
	t := s.setup()
	t.memberRepo.EXPECT().ListByUser(gomock.Any(), "user-1").Return([]*models.OrganizationMember{}, nil)

	orgs, authErr := t.svc.ListByUser(context.Background(), "user-1")
	s.Nil(authErr)
	s.Empty(orgs)
}

func (s *OrgServiceSuite) TestListByUser_Error() {
	t := s.setup()
	t.memberRepo.EXPECT().ListByUser(gomock.Any(), "user-1").Return(nil, errors.New("db error"))

	_, authErr := t.svc.ListByUser(context.Background(), "user-1")
	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

// --- SwitchOrg ---

func (s *OrgServiceSuite) TestSwitchOrg_Success() {
	t := s.setup()
	user := testutil.TestUser()
	member := &models.OrganizationMember{OrgID: "org-1", UserID: user.ID, Role: "admin"}

	t.memberRepo.EXPECT().FindByOrgAndUser(gomock.Any(), "org-1", user.ID).Return(member, nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOrgSwitched, gomock.Any()).Return(nil)

	accessToken, refreshToken, authErr := t.svc.SwitchOrg(context.Background(), user, "org-1")
	s.Nil(authErr)
	s.NotEmpty(accessToken)
	s.NotEmpty(refreshToken)
}

func (s *OrgServiceSuite) TestSwitchOrg_NotMember() {
	t := s.setup()
	user := testutil.TestUser()

	t.memberRepo.EXPECT().FindByOrgAndUser(gomock.Any(), "org-1", user.ID).Return(nil, models.ErrNotFound)

	_, _, authErr := t.svc.SwitchOrg(context.Background(), user, "org-1")
	s.NotNil(authErr)
	s.Equal(types.ErrOrgNotMember, authErr.Code)
}
