package handlers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/session/handlers"
	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type SessionHandlerSuite struct {
	suite.Suite
}

func TestSessionHandlerSuite(t *testing.T) {
	suite.Run(t, new(SessionHandlerSuite))
}

func (s *SessionHandlerSuite) setupHandler() (
	*handlers.SessionHandler,
	*mocks.MockSessionService,
	*mocks.MockEventBus,
	*mocks.MockLogger,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockService := mocks.NewMockSessionService(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(),
		Logger: mockLogger,
		Events: mockEvents,
	}

	handler := handlers.NewSessionHandler(mockService, deps, nil)
	return handler, mockService, mockEvents, mockLogger
}

// authContext returns a context with user/session IDs set.
func authContext(userID, sessionID string) context.Context {
	ctx := context.WithValue(context.Background(), types.UserIDKey, userID)
	ctx = context.WithValue(ctx, types.SessionIDKey, sessionID)
	return ctx
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func (s *SessionHandlerSuite) TestLogin() {
	testUser := testutil.TestUser()
	accessToken := "access-token"
	refreshToken := "refresh-token"

	tests := []struct {
		name       string
		body       string
		setup      func(*mocks.MockSessionService, *mocks.MockEventBus, *mocks.MockLogger)
		wantStatus int
	}{
		{
			name: "success",
			body: `{"email":"test@example.com","password":"password123"}`,
			setup: func(svc *mocks.MockSessionService, events *mocks.MockEventBus, lg *mocks.MockLogger) {
				events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeLogin, gomock.Any()).Return(nil)
				svc.EXPECT().Login(gomock.Any(), gomock.Any(), gomock.Any()).Return(dto.AuthResponse{
					AccessToken:  accessToken,
					RefreshToken: refreshToken,
					User:         dto.UserToDTO(testUser),
					ExpiresIn:    3600,
					Message:      "Login successful",
					SessionID:    "sess-1",
				}, nil)
				events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterLogin, gomock.Any()).Return(nil)
				events.EXPECT().EmitAsync(gomock.Any(), types.EventAuthLoginSuccess, gomock.Any()).Return(nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid JSON body",
			body:       `{invalid`,
			setup:      func(_ *mocks.MockSessionService, _ *mocks.MockEventBus, _ *mocks.MockLogger) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing password",
			body:       `{"email":"test@example.com"}`,
			setup:      func(_ *mocks.MockSessionService, _ *mocks.MockEventBus, _ *mocks.MockLogger) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "before login hook blocks",
			body: `{"email":"test@example.com","password":"password123"}`,
			setup: func(_ *mocks.MockSessionService, events *mocks.MockEventBus, _ *mocks.MockLogger) {
				events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeLogin, gomock.Any()).Return(
					fmt.Errorf("Login blocked"),
				)
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "invalid credentials",
			body: `{"email":"test@example.com","password":"wrong"}`,
			setup: func(svc *mocks.MockSessionService, events *mocks.MockEventBus, _ *mocks.MockLogger) {
				events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeLogin, gomock.Any()).Return(nil)
				svc.EXPECT().Login(gomock.Any(), gomock.Any(), gomock.Any()).Return(
					dto.AuthResponse{}, types.NewInvalidCredentialsError(),
				)
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, mockEvents, mockLogger := s.setupHandler()
			tt.setup(mockService, mockEvents, mockLogger)

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.Login(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[dto.AuthResponse]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.NotNil(resp.Data.AccessToken)
				s.NotNil(resp.Data.RefreshToken)
				s.NotNil(resp.Data.User)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

func (s *SessionHandlerSuite) TestLogout() {
	tests := []struct {
		name       string
		ctx        context.Context
		setup      func(*mocks.MockSessionService, *mocks.MockEventBus, *mocks.MockLogger)
		wantStatus int
	}{
		{
			name: "success",
			ctx:  authContext("user-1", "sess-1"),
			setup: func(svc *mocks.MockSessionService, events *mocks.MockEventBus, _ *mocks.MockLogger) {
				svc.EXPECT().Logout(gomock.Any(), "user-1", "sess-1").Return(nil)
				events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterLogout, gomock.Any()).Return(nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			ctx:        context.Background(),
			setup:      func(_ *mocks.MockSessionService, _ *mocks.MockEventBus, _ *mocks.MockLogger) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "no session ID in context",
			ctx:  context.WithValue(context.Background(), types.UserIDKey, "user-1"),
			setup: func(_ *mocks.MockSessionService, _ *mocks.MockEventBus, _ *mocks.MockLogger) {
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "service error - session not found",
			ctx:  authContext("user-1", "nonexistent"),
			setup: func(svc *mocks.MockSessionService, _ *mocks.MockEventBus, _ *mocks.MockLogger) {
				svc.EXPECT().Logout(gomock.Any(), "user-1", "nonexistent").Return(types.NewSessionNotFoundError())
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, mockEvents, mockLogger := s.setupHandler()
			tt.setup(mockService, mockEvents, mockLogger)

			req := httptest.NewRequest(http.MethodPost, "/logout", nil)
			req = req.WithContext(tt.ctx)
			rr := httptest.NewRecorder()

			handler.Logout(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

func (s *SessionHandlerSuite) TestRefresh() {
	accessToken := "new-access"
	refreshToken := "new-refresh"

	tests := []struct {
		name       string
		body       string
		setup      func(*mocks.MockSessionService)
		wantStatus int
	}{
		{
			name: "success from body",
			body: `{"refresh_token":"valid-token"}`,
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().Refresh(gomock.Any(), gomock.Any()).Return(dto.AuthResponse{
					AccessToken:  accessToken,
					RefreshToken: refreshToken,
					ExpiresIn:    3600,
					SessionID:    "sess-new",
				}, nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "empty refresh token",
			body: `{}`,
			setup: func(_ *mocks.MockSessionService) {
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "service error - invalid credentials",
			body: `{"refresh_token":"expired-token"}`,
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().Refresh(gomock.Any(), gomock.Any()).Return(
					dto.AuthResponse{}, types.NewInvalidCredentialsError(),
				)
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.Refresh(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[dto.AuthResponse]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.NotNil(resp.Data.AccessToken)
				s.NotNil(resp.Data.RefreshToken)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ListSessions
// ---------------------------------------------------------------------------

func (s *SessionHandlerSuite) TestListSessions() {
	session1 := dto.SessionDTO{
		ID:        "sess-1",
		IPAddress: "127.0.0.1",
		UserAgent: "TestAgent",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Current:   true,
	}
	session2 := dto.SessionDTO{
		ID:        "sess-2",
		IPAddress: "192.168.1.1",
		UserAgent: "OtherAgent",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Current:   false,
	}

	tests := []struct {
		name       string
		ctx        context.Context
		setup      func(*mocks.MockSessionService)
		wantStatus int
		wantTotal  int64
	}{
		{
			name: "success",
			ctx:  authContext("user-1", "sess-1"),
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().ListSessions(gomock.Any(), "user-1", gomock.Any(), gomock.Any()).Return(
					[]dto.SessionDTO{session1, session2}, int64(2), nil,
				)
			},
			wantStatus: http.StatusOK,
			wantTotal:  2,
		},
		{
			name:       "no user in context",
			ctx:        context.Background(),
			setup:      func(_ *mocks.MockSessionService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "service error",
			ctx:  authContext("user-1", "sess-1"),
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().ListSessions(gomock.Any(), "user-1", gomock.Any(), gomock.Any()).Return(
					nil, int64(0), types.NewInternalError("db error"),
				)
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
			req = req.WithContext(tt.ctx)
			rr := httptest.NewRecorder()

			handler.ListSessions(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[types.ListResponse[dto.SessionDTO]]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Equal(tt.wantTotal, resp.Data.Total)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetSession
// ---------------------------------------------------------------------------

func (s *SessionHandlerSuite) TestGetSession() {
	sessionDTO := &dto.SessionDTO{
		ID:        "sess-1",
		IPAddress: "127.0.0.1",
		UserAgent: "TestAgent",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	tests := []struct {
		name       string
		ctx        context.Context
		path       string
		sessionID  string
		setup      func(*mocks.MockSessionService)
		wantStatus int
	}{
		{
			name:      "success",
			ctx:       authContext("user-1", "sess-1"),
			path:      "/sessions/sess-1",
			sessionID: "sess-1",
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().GetSession(gomock.Any(), "user-1", "sess-1").Return(sessionDTO, nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			ctx:        context.Background(),
			path:       "/sessions/sess-1",
			sessionID:  "sess-1",
			setup:      func(_ *mocks.MockSessionService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:      "not found",
			ctx:       authContext("user-1", "sess-1"),
			path:      "/sessions/nonexistent",
			sessionID: "nonexistent",
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().GetSession(gomock.Any(), "user-1", "nonexistent").Return(nil, types.NewSessionNotFoundError())
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req = req.WithContext(tt.ctx)
			req.SetPathValue("session_id", tt.sessionID)
			rr := httptest.NewRecorder()

			handler.GetSession(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// DeleteSession
// ---------------------------------------------------------------------------

func (s *SessionHandlerSuite) TestDeleteSession() {
	tests := []struct {
		name       string
		ctx        context.Context
		path       string
		sessionID  string
		setup      func(*mocks.MockSessionService)
		wantStatus int
	}{
		{
			name:      "success",
			ctx:       authContext("user-1", "sess-1"),
			path:      "/sessions/sess-1",
			sessionID: "sess-1",
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().DeleteSession(gomock.Any(), "user-1", "sess-1").Return(nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			ctx:        context.Background(),
			path:       "/sessions/sess-1",
			sessionID:  "sess-1",
			setup:      func(_ *mocks.MockSessionService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:      "unauthorized - different user",
			ctx:       authContext("user-1", "sess-1"),
			path:      "/sessions/sess-other",
			sessionID: "sess-other",
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().DeleteSession(gomock.Any(), "user-1", "sess-other").Return(types.NewUnauthorizedError())
			},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodDelete, tt.path, nil)
			req = req.WithContext(tt.ctx)
			req.SetPathValue("session_id", tt.sessionID)
			rr := httptest.NewRecorder()

			handler.DeleteSession(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// DeleteAllSessions
// ---------------------------------------------------------------------------

func (s *SessionHandlerSuite) TestDeleteAllSessions() {
	tests := []struct {
		name       string
		ctx        context.Context
		setup      func(*mocks.MockSessionService)
		wantStatus int
	}{
		{
			name: "success",
			ctx:  authContext("user-1", "sess-1"),
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().DeleteAllSessions(gomock.Any(), "user-1").Return(nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			ctx:        context.Background(),
			setup:      func(_ *mocks.MockSessionService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "service error",
			ctx:  authContext("user-1", "sess-1"),
			setup: func(svc *mocks.MockSessionService) {
				svc.EXPECT().DeleteAllSessions(gomock.Any(), "user-1").Return(types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodDelete, "/sessions", nil)
			req = req.WithContext(tt.ctx)
			rr := httptest.NewRecorder()

			handler.DeleteAllSessions(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}
