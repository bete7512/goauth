package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/audit/handlers"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type AuditHandlerSuite struct {
	suite.Suite
}

func TestAuditHandlerSuite(t *testing.T) {
	suite.Run(t, new(AuditHandlerSuite))
}

func (s *AuditHandlerSuite) setupHandler() (*handlers.AuditHandler, *mocks.MockAuditService) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockService := mocks.NewMockAuditService(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(),
		Logger: mockLogger,
	}

	handler := handlers.NewAuditHandler(deps, mockService)
	return handler, mockService
}

func testAuditLog(id, action, actorID string) *models.AuditLog {
	return &models.AuditLog{
		ID:        id,
		Action:    action,
		ActorID:   actorID,
		ActorType: "user",
		Severity:  "info",
		Details:   "test",
		CreatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// GetMyAuditLogs
// ---------------------------------------------------------------------------

func (s *AuditHandlerSuite) TestGetMyAuditLogs() {
	log1 := testAuditLog("log-1", "auth.login.success", "user-1")

	tests := []struct {
		name       string
		userID     string
		setup      func(*mocks.MockAuditService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetMyAuditLogs(gomock.Any(), "user-1", gomock.Any()).Return([]*models.AuditLog{log1}, int64(1), nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			userID:     "",
			setup:      func(svc *mocks.MockAuditService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:   "service error",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetMyAuditLogs(gomock.Any(), "user-1", gomock.Any()).Return(nil, int64(0), types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/me/audit", nil)
			if tt.userID != "" {
				req = req.WithContext(testutil.ContextWithUserID(req.Context(), tt.userID))
			}
			rr := httptest.NewRecorder()

			handler.GetMyAuditLogs(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[types.ListResponse[*models.AuditLog]]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Equal(int64(1), resp.Data.Total)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetMyLogins
// ---------------------------------------------------------------------------

func (s *AuditHandlerSuite) TestGetMyLogins() {
	tests := []struct {
		name       string
		userID     string
		setup      func(*mocks.MockAuditService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetMyLogins(gomock.Any(), "user-1", gomock.Any()).Return([]*models.AuditLog{}, int64(0), nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			userID:     "",
			setup:      func(svc *mocks.MockAuditService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:   "service error",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetMyLogins(gomock.Any(), "user-1", gomock.Any()).Return(nil, int64(0), types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/me/audit/logins", nil)
			if tt.userID != "" {
				req = req.WithContext(testutil.ContextWithUserID(req.Context(), tt.userID))
			}
			rr := httptest.NewRecorder()

			handler.GetMyLogins(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// GetMyChanges
// ---------------------------------------------------------------------------

func (s *AuditHandlerSuite) TestGetMyChanges() {
	tests := []struct {
		name       string
		userID     string
		setup      func(*mocks.MockAuditService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetMyChanges(gomock.Any(), "user-1", gomock.Any()).Return([]*models.AuditLog{}, int64(0), nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			userID:     "",
			setup:      func(svc *mocks.MockAuditService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:   "service error",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetMyChanges(gomock.Any(), "user-1", gomock.Any()).Return(nil, int64(0), types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/me/audit/changes", nil)
			if tt.userID != "" {
				req = req.WithContext(testutil.ContextWithUserID(req.Context(), tt.userID))
			}
			rr := httptest.NewRecorder()

			handler.GetMyChanges(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// GetMySecurity
// ---------------------------------------------------------------------------

func (s *AuditHandlerSuite) TestGetMySecurity() {
	tests := []struct {
		name       string
		userID     string
		setup      func(*mocks.MockAuditService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetMySecurity(gomock.Any(), "user-1", gomock.Any()).Return([]*models.AuditLog{}, int64(0), nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			userID:     "",
			setup:      func(svc *mocks.MockAuditService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:   "service error",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetMySecurity(gomock.Any(), "user-1", gomock.Any()).Return(nil, int64(0), types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/me/audit/security", nil)
			if tt.userID != "" {
				req = req.WithContext(testutil.ContextWithUserID(req.Context(), tt.userID))
			}
			rr := httptest.NewRecorder()

			handler.GetMySecurity(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// AdminListAuditLogs
// ---------------------------------------------------------------------------

func (s *AuditHandlerSuite) TestAdminListAuditLogs() {
	log1 := testAuditLog("log-1", "auth.login.success", "user-1")

	tests := []struct {
		name       string
		setup      func(*mocks.MockAuditService)
		wantStatus int
		wantTotal  int64
	}{
		{
			name: "success",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().ListAllAuditLogs(gomock.Any(), gomock.Any()).Return([]*models.AuditLog{log1}, int64(1), nil)
			},
			wantStatus: http.StatusOK,
			wantTotal:  1,
		},
		{
			name: "empty list",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().ListAllAuditLogs(gomock.Any(), gomock.Any()).Return([]*models.AuditLog{}, int64(0), nil)
			},
			wantStatus: http.StatusOK,
			wantTotal:  0,
		},
		{
			name: "service error",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().ListAllAuditLogs(gomock.Any(), gomock.Any()).Return(nil, int64(0), types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
			rr := httptest.NewRecorder()

			handler.AdminListAuditLogs(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[types.ListResponse[*models.AuditLog]]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Equal(tt.wantTotal, resp.Data.Total)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AdminGetUserAudit
// ---------------------------------------------------------------------------

func (s *AuditHandlerSuite) TestAdminGetUserAudit() {
	log1 := testAuditLog("log-1", "auth.login.success", "user-1")

	tests := []struct {
		name       string
		userID     string
		setup      func(*mocks.MockAuditService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetUserAuditLogs(gomock.Any(), "user-1", gomock.Any()).Return([]*models.AuditLog{log1}, int64(1), nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "service error",
			userID: "user-1",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetUserAuditLogs(gomock.Any(), "user-1", gomock.Any()).Return(nil, int64(0), types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/admin/audit/users/"+tt.userID, nil)
			req.SetPathValue("id", tt.userID)
			rr := httptest.NewRecorder()

			handler.AdminGetUserAudit(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// AdminGetActionAudit
// ---------------------------------------------------------------------------

func (s *AuditHandlerSuite) TestAdminGetActionAudit() {
	log1 := testAuditLog("log-1", "auth.login.success", "user-1")

	tests := []struct {
		name       string
		action     string
		setup      func(*mocks.MockAuditService)
		wantStatus int
	}{
		{
			name:   "success",
			action: "auth.login.success",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetAuditLogsByAction(gomock.Any(), "auth.login.success", gomock.Any()).Return([]*models.AuditLog{log1}, int64(1), nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "service error",
			action: "auth.login.success",
			setup: func(svc *mocks.MockAuditService) {
				svc.EXPECT().GetAuditLogsByAction(gomock.Any(), "auth.login.success", gomock.Any()).Return(nil, int64(0), types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/admin/audit/actions/"+tt.action, nil)
			req.SetPathValue("action", tt.action)
			rr := httptest.NewRecorder()

			handler.AdminGetActionAudit(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}
