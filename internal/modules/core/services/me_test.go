package core_services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type MeServiceSuite struct {
	suite.Suite
}

func TestMeServiceSuite(t *testing.T) {
	suite.Run(t, new(MeServiceSuite))
}

func (s *MeServiceSuite) setupService() (
	core_services.CoreService,
	*mocks.MockUserRepository,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenRepo := mocks.NewMockTokenRepository(ctrl)
	mockVerifRepo := mocks.NewMockVerificationTokenRepository(ctrl)
	mockExtAttrRepo := mocks.NewMockExtendedAttributeRepository(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	secMgr := testutil.TestSecurityManager()
	cfg := testutil.TestCoreConfig()

	deps := config.ModuleDependencies{
		Config:          testutil.TestConfig(),
		Events:          mockEvents,
		Logger:          mockLogger,
		SecurityManager: secMgr,
	}

	svc := core_services.NewCoreService(deps, mockUserRepo, mockExtAttrRepo, mockTokenRepo, mockVerifRepo, mockLogger, secMgr, cfg)
	return svc, mockUserRepo
}

func (s *MeServiceSuite) TestGetCurrentUser() {
	tests := []struct {
		name       string
		overrideID string
		setup      func(*models.User, *mocks.MockUserRepository)
		wantErr    bool
		errCode    types.ErrorCode
		wantEmail  string
	}{
		{
			name: "success",
			setup: func(u *models.User, ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
			},
			wantEmail: "test@example.com",
		},
		{
			name: "returns all user fields",
			setup: func(u *models.User, ur *mocks.MockUserRepository) {
				u.Username = "testuser"
				u.PhoneNumber = "+1234567890"
				u.Avatar = "https://example.com/avatar.png"
				u.ExtendedAttributes = []models.ExtendedAttributes{
					{Name: "role", Value: "admin"},
				}
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
			},
		},
		{
			name:       "user not found",
			overrideID: "nonexistent",
			setup: func(_ *models.User, ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), "nonexistent").Return(nil, errors.New("not found"))
			},
			wantErr: true,
			errCode: types.ErrUserNotFound,
		},
		{
			name:       "nil user returned",
			overrideID: "some-id",
			setup: func(_ *models.User, ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), "some-id").Return(nil, nil)
			},
			wantErr: true,
			errCode: types.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			testUser := testutil.TestUser()
			svc, mockUserRepo := s.setupService()
			tt.setup(testUser, mockUserRepo)

			userID := testUser.ID
			if tt.overrideID != "" {
				userID = tt.overrideID
			}

			resp, goauthErr := svc.GetCurrentUser(context.Background(), userID)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
				s.Equal(testUser.ID, resp.ID)
				s.Equal(testUser.Email, resp.Email)
				if tt.wantEmail != "" {
					s.Equal(tt.wantEmail, resp.Email)
				}
				if testUser.Username != "" {
					s.Equal(testUser.Username, resp.Username)
				}
			}
		})
	}
}
