package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/session/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type LoginServiceSuite struct {
	suite.Suite
}

func TestLoginServiceSuite(t *testing.T) {
	suite.Run(t, new(LoginServiceSuite))
}

func (s *LoginServiceSuite) setupService() (
	services.SessionService,
	*mocks.MockUserRepository,
	*mocks.MockSessionRepository,
	*mocks.MockLogger,
	*mocks.MockEventBus,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockSessionRepo := mocks.NewMockSessionRepository(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)

	secMgr := testutil.TestSecurityManager()
	cfg := testutil.TestSessionModuleConfig()

	deps := config.ModuleDependencies{
		Config:          testutil.TestConfig(),
		Events:          mockEvents,
		Logger:          mockLogger,
		SecurityManager: secMgr,
	}

	svc := services.NewSessionService(deps, mockUserRepo, mockSessionRepo, mockLogger, secMgr, cfg)
	return svc, mockUserRepo, mockSessionRepo, mockLogger, mockEvents
}

func (s *LoginServiceSuite) TestLogin() {
	tests := []struct {
		name       string
		req        *dto.LoginRequest
		metadata   *types.RequestMetadata
		setup      func(*models.User, *mocks.MockUserRepository, *mocks.MockSessionRepository, *mocks.MockLogger, *mocks.MockEventBus)
		wantErr    bool
		errCode    types.ErrorCode
		statusCode int
	}{
		{
			name:     "success with email",
			req:      &dto.LoginRequest{Email: "test@example.com", Password: "password123"},
			metadata: &types.RequestMetadata{IPAddress: "127.0.0.1", UserAgent: "TestAgent/1.0"},
			setup: func(u *models.User, ur *mocks.MockUserRepository, sr *mocks.MockSessionRepository, lg *mocks.MockLogger, me *mocks.MockEventBus) {
				ur.EXPECT().FindByEmail(gomock.Any(), "test@example.com").Return(u, nil)
				me.EXPECT().EmitSync(gomock.Any(), types.EventAfterPasswordVerified, gomock.Any()).Return(nil)
				sr.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Session{})).Return(nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
			},
		},
		{
			name:     "user not found",
			req:      &dto.LoginRequest{Email: "unknown@example.com", Password: "password123"},
			metadata: &types.RequestMetadata{IPAddress: "127.0.0.1", UserAgent: "TestAgent/1.0"},
			setup: func(_ *models.User, ur *mocks.MockUserRepository, _ *mocks.MockSessionRepository, _ *mocks.MockLogger, _ *mocks.MockEventBus) {
				ur.EXPECT().FindByEmail(gomock.Any(), "unknown@example.com").Return(nil, errors.New("not found"))
			},
			wantErr:    true,
			errCode:    types.ErrInvalidCredentials,
			statusCode: 401,
		},
		{
			name:     "wrong password",
			req:      &dto.LoginRequest{Email: "test@example.com", Password: "wrongpassword"},
			metadata: &types.RequestMetadata{IPAddress: "127.0.0.1", UserAgent: "TestAgent/1.0"},
			setup: func(u *models.User, ur *mocks.MockUserRepository, _ *mocks.MockSessionRepository, _ *mocks.MockLogger, _ *mocks.MockEventBus) {
				ur.EXPECT().FindByEmail(gomock.Any(), "test@example.com").Return(u, nil)
			},
			wantErr:    true,
			errCode:    types.ErrInvalidCredentials,
			statusCode: 401,
		},
		{
			name:     "session create fails",
			req:      &dto.LoginRequest{Email: "test@example.com", Password: "password123"},
			metadata: &types.RequestMetadata{IPAddress: "127.0.0.1", UserAgent: "TestAgent/1.0"},
			setup: func(u *models.User, ur *mocks.MockUserRepository, sr *mocks.MockSessionRepository, _ *mocks.MockLogger, me *mocks.MockEventBus) {
				ur.EXPECT().FindByEmail(gomock.Any(), "test@example.com").Return(u, nil)
				me.EXPECT().EmitSync(gomock.Any(), types.EventAfterPasswordVerified, gomock.Any()).Return(nil)
				sr.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Session{})).Return(errors.New("db error"))
			},
			wantErr:    true,
			errCode:    types.ErrInternalError,
			statusCode: 500,
		},
		{
			name:     "update last login fails - still succeeds",
			req:      &dto.LoginRequest{Email: "test@example.com", Password: "password123"},
			metadata: &types.RequestMetadata{IPAddress: "127.0.0.1", UserAgent: "TestAgent/1.0"},
			setup: func(u *models.User, ur *mocks.MockUserRepository, sr *mocks.MockSessionRepository, lg *mocks.MockLogger, me *mocks.MockEventBus) {
				ur.EXPECT().FindByEmail(gomock.Any(), "test@example.com").Return(u, nil)
				me.EXPECT().EmitSync(gomock.Any(), types.EventAfterPasswordVerified, gomock.Any()).Return(nil)
				sr.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Session{})).Return(nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(errors.New("update failed"))
				lg.EXPECT().Errorf(gomock.Any(), gomock.Any())
			},
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			testUser := testutil.TestUser()
			svc, mockUserRepo, mockSessionRepo, mockLogger, mockEvents := s.setupService()
			tt.setup(testUser, mockUserRepo, mockSessionRepo, mockLogger, mockEvents)

			resp, goauthErr := svc.Login(context.Background(), tt.req, tt.metadata)

			if tt.wantErr {
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
				s.Equal(tt.statusCode, goauthErr.StatusCode)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp.AccessToken)
				s.NotNil(resp.RefreshToken)
				s.NotNil(resp.User)
			}
		})
	}
}
