package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/session/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type SessionsServiceSuite struct {
	suite.Suite
}

func TestSessionsServiceSuite(t *testing.T) {
	suite.Run(t, new(SessionsServiceSuite))
}

func (s *SessionsServiceSuite) setupService() (
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

func (s *SessionsServiceSuite) TestListSessions() {
	testUser := testutil.TestUser()
	session1 := testutil.TestSession(testUser.ID)
	session2 := testutil.TestSession(testUser.ID)

	opts := models.SessionListOpts{}
	opts.Normalize(100)

	tests := []struct {
		name             string
		userID           string
		currentSessionID string
		setup            func(*mocks.MockSessionRepository)
		wantErr          bool
		errCode          types.ErrorCode
		wantCount        int
	}{
		{
			name:             "success with current session marked",
			userID:           testUser.ID,
			currentSessionID: session1.ID,
			setup: func(sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByUserID(gomock.Any(), testUser.ID, gomock.Any()).Return([]*models.Session{session1, session2}, int64(2), nil)
			},
			wantCount: 2,
		},
		{
			name:   "empty sessions",
			userID: testUser.ID,
			setup: func(sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByUserID(gomock.Any(), testUser.ID, gomock.Any()).Return([]*models.Session{}, int64(0), nil)
			},
			wantCount: 0,
		},
		{
			name:   "db error",
			userID: testUser.ID,
			setup: func(sr *mocks.MockSessionRepository) {
				sr.EXPECT().FindByUserID(gomock.Any(), testUser.ID, gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
			errCode: types.ErrInternalError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockSessionRepo := s.setupService()
			tt.setup(mockSessionRepo)

			sessions, total, goauthErr := svc.ListSessions(context.Background(), tt.userID, tt.currentSessionID, opts)

			if tt.wantErr {
				s.Nil(sessions)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
				s.Equal(tt.wantCount, len(sessions))
				s.Equal(int64(tt.wantCount), total)
			}
		})
	}
}

func (s *SessionsServiceSuite) TestGetSession() {
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
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockSessionRepo := s.setupService()
			tt.setup(mockSessionRepo)

			resp, goauthErr := svc.GetSession(context.Background(), tt.userID, tt.sessionID)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
				s.Equal(testSession.ID, resp.ID)
			}
		})
	}
}

func (s *SessionsServiceSuite) TestDeleteSession() {
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
			name:      "unauthorized - different user",
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

			goauthErr := svc.DeleteSession(context.Background(), tt.userID, tt.sessionID)

			if tt.wantErr {
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
			}
		})
	}
}

func (s *SessionsServiceSuite) TestDeleteAllSessions() {
	tests := []struct {
		name    string
		userID  string
		setup   func(*mocks.MockSessionRepository)
		wantErr bool
		errCode types.ErrorCode
	}{
		{
			name:   "success",
			userID: "user-1",
			setup: func(sr *mocks.MockSessionRepository) {
				sr.EXPECT().DeleteByUserID(gomock.Any(), "user-1").Return(nil)
			},
		},
		{
			name:   "db error",
			userID: "user-1",
			setup: func(sr *mocks.MockSessionRepository) {
				sr.EXPECT().DeleteByUserID(gomock.Any(), "user-1").Return(errors.New("db error"))
			},
			wantErr: true,
			errCode: types.ErrInternalError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockSessionRepo := s.setupService()
			tt.setup(mockSessionRepo)

			goauthErr := svc.DeleteAllSessions(context.Background(), tt.userID)

			if tt.wantErr {
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
			}
		})
	}
}
