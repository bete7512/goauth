package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/session/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type LogoutServiceSuite struct {
	suite.Suite
}

func TestLogoutServiceSuite(t *testing.T) {
	suite.Run(t, new(LogoutServiceSuite))
}

func (s *LogoutServiceSuite) setupService() (
	services.SessionService,
	*mocks.MockSessionRepository,
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
	return svc, mockSessionRepo
}

func (s *LogoutServiceSuite) TestLogout() {
	testUser := testutil.TestUser()
	testSession := testutil.TestSession(testUser.ID)

	tests := []struct {
		name      string
		userID    string
		sessionID string
		setup     func(*mocks.MockSessionRepository)
		wantErr   bool
		errCode   types.ErrorCode
	}{
		{
			name:      "success",
			userID:    testUser.ID,
			sessionID: testSession.ID,
			setup: func(sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByID(gomock.Any(), testSession.ID).Return(testSession, nil)
				sr.EXPECT().Delete(gomock.Any(), testSession.ID).Return(nil)
			},
		},
		{
			name:      "session not found",
			userID:    testUser.ID,
			sessionID: "nonexistent",
			setup: func(sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByID(gomock.Any(), "nonexistent").Return(nil, errors.New("not found"))
			},
			wantErr: true,
			errCode: types.ErrSessionNotFound,
		},
		{
			name:      "session belongs to different user",
			userID:    "other-user",
			sessionID: testSession.ID,
			setup: func(sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByID(gomock.Any(), testSession.ID).Return(testSession, nil)
			},
			wantErr: true,
			errCode: types.ErrUnauthorized,
		},
		{
			name:      "delete fails",
			userID:    testUser.ID,
			sessionID: testSession.ID,
			setup: func(sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByID(gomock.Any(), testSession.ID).Return(testSession, nil)
				sr.EXPECT().Delete(gomock.Any(), testSession.ID).Return(errors.New("db error"))
			},
			wantErr: true,
			errCode: types.ErrInternalError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockSessionRepo := s.setupService()
			tt.setup(mockSessionRepo)

			goauthErr := svc.Logout(context.Background(), tt.userID, tt.sessionID)

			if tt.wantErr {
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
			}
		})
	}
}
