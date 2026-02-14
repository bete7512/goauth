package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

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

type RefreshServiceSuite struct {
	suite.Suite
}

func TestRefreshServiceSuite(t *testing.T) {
	suite.Run(t, new(RefreshServiceSuite))
}

func (s *RefreshServiceSuite) setupService() (
	services.SessionService,
	*mocks.MockUserRepository,
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
	return svc, mockUserRepo, mockSessionRepo
}

func (s *RefreshServiceSuite) TestRefresh() {
	testUser := testutil.TestUser()

	validSession := &models.Session{
		ID:                    "sess-1",
		UserID:                testUser.ID,
		RefreshToken:          "valid-refresh-token",
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
		ExpiresAt:             time.Now().Add(1 * time.Hour),
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	expiredSession := &models.Session{
		ID:                    "sess-expired",
		UserID:                testUser.ID,
		RefreshToken:          "expired-session-token",
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
		ExpiresAt:             time.Now().Add(-1 * time.Hour),
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	expiredRefreshSession := &models.Session{
		ID:                    "sess-expired-refresh",
		UserID:                testUser.ID,
		RefreshToken:          "expired-refresh-token",
		RefreshTokenExpiresAt: time.Now().Add(-1 * time.Hour),
		ExpiresAt:             time.Now().Add(1 * time.Hour),
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	tests := []struct {
		name       string
		req        *dto.RefreshRequest
		setup      func(*mocks.MockUserRepository, *mocks.MockSessionRepository)
		wantErr    bool
		errCode    types.ErrorCode
		statusCode int
	}{
		{
			name: "success",
			req:  &dto.RefreshRequest{RefreshToken: "valid-refresh-token"},
			setup: func(ur *mocks.MockUserRepository, sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByToken(gomock.Any(), "valid-refresh-token").Return(validSession, nil)
				ur.EXPECT().FindByID(gomock.Any(), testUser.ID).Return(testUser, nil)
				sr.EXPECT().DeleteByToken(gomock.Any(), "valid-refresh-token").Return(nil)
				sr.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Session{})).Return(nil)
			},
		},
		{
			name: "session not found",
			req:  &dto.RefreshRequest{RefreshToken: "unknown-token"},
			setup: func(_ *mocks.MockUserRepository, sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByToken(gomock.Any(), "unknown-token").Return(nil, errors.New("not found"))
			},
			wantErr:    true,
			errCode:    types.ErrInvalidCredentials,
			statusCode: 401,
		},
		{
			name: "session expired",
			req:  &dto.RefreshRequest{RefreshToken: "expired-session-token"},
			setup: func(_ *mocks.MockUserRepository, sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByToken(gomock.Any(), "expired-session-token").Return(expiredSession, nil)
			},
			wantErr:    true,
			errCode:    types.ErrInvalidCredentials,
			statusCode: 401,
		},
		{
			name: "refresh token expired",
			req:  &dto.RefreshRequest{RefreshToken: "expired-refresh-token"},
			setup: func(_ *mocks.MockUserRepository, sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByToken(gomock.Any(), "expired-refresh-token").Return(expiredRefreshSession, nil)
			},
			wantErr:    true,
			errCode:    types.ErrInvalidCredentials,
			statusCode: 401,
		},
		{
			name: "user not found",
			req:  &dto.RefreshRequest{RefreshToken: "valid-refresh-token"},
			setup: func(ur *mocks.MockUserRepository, sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByToken(gomock.Any(), "valid-refresh-token").Return(validSession, nil)
				ur.EXPECT().FindByID(gomock.Any(), testUser.ID).Return(nil, errors.New("not found"))
			},
			wantErr:    true,
			errCode:    types.ErrInvalidCredentials,
			statusCode: 401,
		},
		{
			name: "delete old session fails",
			req:  &dto.RefreshRequest{RefreshToken: "valid-refresh-token"},
			setup: func(ur *mocks.MockUserRepository, sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByToken(gomock.Any(), "valid-refresh-token").Return(validSession, nil)
				ur.EXPECT().FindByID(gomock.Any(), testUser.ID).Return(testUser, nil)
				sr.EXPECT().DeleteByToken(gomock.Any(), "valid-refresh-token").Return(errors.New("db error"))
			},
			wantErr:    true,
			errCode:    types.ErrInternalError,
			statusCode: 500,
		},
		{
			name: "create new session fails",
			req:  &dto.RefreshRequest{RefreshToken: "valid-refresh-token"},
			setup: func(ur *mocks.MockUserRepository, sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByToken(gomock.Any(), "valid-refresh-token").Return(validSession, nil)
				ur.EXPECT().FindByID(gomock.Any(), testUser.ID).Return(testUser, nil)
				sr.EXPECT().DeleteByToken(gomock.Any(), "valid-refresh-token").Return(nil)
				sr.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Session{})).Return(errors.New("db error"))
			},
			wantErr:    true,
			errCode:    types.ErrInternalError,
			statusCode: 500,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, mockSessionRepo := s.setupService()
			tt.setup(mockUserRepo, mockSessionRepo)

			resp, goauthErr := svc.Refresh(context.Background(), tt.req)

			if tt.wantErr {
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
				s.Equal(tt.statusCode, goauthErr.StatusCode)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp.AccessToken)
				s.NotNil(resp.RefreshToken)
				s.NotEmpty(resp.SessionID)
			}
		})
	}
}
