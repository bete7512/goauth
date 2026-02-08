package handlers_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/core/handlers"
	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type CoreHandlerSuite struct {
	suite.Suite
}

func TestCoreHandlerSuite(t *testing.T) {
	suite.Run(t, new(CoreHandlerSuite))
}

func (s *CoreHandlerSuite) setupHandler() (*handlers.CoreHandler, *mocks.MockCoreService, *mocks.MockEventBus, *mocks.MockLogger) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockService := mocks.NewMockCoreService(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(),
		Events: mockEvents,
		Logger: mockLogger,
	}

	handler := handlers.NewCoreHandler(mockService, deps)
	return handler, mockService, mockEvents, mockLogger
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

func (s *CoreHandlerSuite) TestSignup() {
	tests := []struct {
		name       string
		body       string
		setup      func(*mocks.MockCoreService, *mocks.MockEventBus, *mocks.MockLogger)
		wantStatus int
	}{
		{
			name: "success",
			body: `{"email":"new@example.com","password":"password123"}`,
			setup: func(svc *mocks.MockCoreService, events *mocks.MockEventBus, logger *mocks.MockLogger) {
				userDTO := &dto.UserDTO{ID: "user-1", Email: "new@example.com"}
				svc.EXPECT().Signup(gomock.Any(), gomock.Any()).Return(&dto.AuthResponse{
					User:    userDTO,
					Message: "Signup successful",
				}, nil)
				events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeSignup, gomock.Any()).Return(nil)
				events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterSignup, gomock.Any()).Return(nil)
			},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "invalid JSON",
			body:       `{invalid`,
			setup:      func(svc *mocks.MockCoreService, events *mocks.MockEventBus, logger *mocks.MockLogger) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - missing email and username",
			body:       `{"password":"password123"}`,
			setup:      func(svc *mocks.MockCoreService, events *mocks.MockEventBus, logger *mocks.MockLogger) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - password too short",
			body:       `{"email":"new@example.com","password":"ab"}`,
			setup:      func(svc *mocks.MockCoreService, events *mocks.MockEventBus, logger *mocks.MockLogger) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "before signup hook blocks",
			body: `{"email":"new@example.com","password":"password123"}`,
			setup: func(svc *mocks.MockCoreService, events *mocks.MockEventBus, logger *mocks.MockLogger) {
				events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeSignup, gomock.Any()).Return(
					errors.New("blocked"),
				)
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "service error",
			body: `{"email":"new@example.com","password":"password123"}`,
			setup: func(svc *mocks.MockCoreService, events *mocks.MockEventBus, logger *mocks.MockLogger) {
				events.EXPECT().EmitSync(gomock.Any(), types.EventBeforeSignup, gomock.Any()).Return(nil)
				svc.EXPECT().Signup(gomock.Any(), gomock.Any()).Return(nil, types.NewGoAuthError(
					types.ErrUserAlreadyExists, "email taken", http.StatusConflict,
				))
			},
			wantStatus: http.StatusConflict,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, mockEvents, mockLogger := s.setupHandler()
			tt.setup(mockService, mockEvents, mockLogger)

			req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.Signup(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusCreated {
				var resp types.APIResponse[*dto.AuthResponse]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.NotNil(resp.Data)
				s.NotNil(resp.Data.User)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Me
// ---------------------------------------------------------------------------

func (s *CoreHandlerSuite) TestMe() {
	userDTO := &dto.UserDTO{ID: "user-1", Email: "test@example.com", Name: "Test User"}

	tests := []struct {
		name       string
		userID     string
		setup      func(*mocks.MockCoreService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: "user-1",
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().GetProfile(gomock.Any(), "user-1").Return(userDTO, nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			userID:     "",
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:   "service error",
			userID: "user-1",
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().GetProfile(gomock.Any(), "user-1").Return(nil, types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tt.userID != "" {
				req = testutil.AuthenticatedRequest(req, tt.userID)
			}
			rr := httptest.NewRecorder()

			handler.Me(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[*dto.UserDTO]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Equal("user-1", resp.Data.ID)
				s.Equal("test@example.com", resp.Data.Email)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateProfile
// ---------------------------------------------------------------------------

func (s *CoreHandlerSuite) TestUpdateProfile() {
	userDTO := &dto.UserDTO{ID: "user-1", Email: "test@example.com", Name: "Updated Name"}

	tests := []struct {
		name       string
		userID     string
		body       string
		setup      func(*mocks.MockCoreService, *mocks.MockEventBus)
		wantStatus int
	}{
		{
			name:   "success",
			userID: "user-1",
			body:   `{"name":"Updated Name"}`,
			setup: func(svc *mocks.MockCoreService, events *mocks.MockEventBus) {
				svc.EXPECT().UpdateProfile(gomock.Any(), "user-1", gomock.Any()).Return(userDTO, nil)
				events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterChangeProfile, gomock.Any()).Return(nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			userID:     "",
			body:       `{"name":"Updated Name"}`,
			setup:      func(svc *mocks.MockCoreService, events *mocks.MockEventBus) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid JSON",
			userID:     "user-1",
			body:       `{invalid`,
			setup:      func(svc *mocks.MockCoreService, events *mocks.MockEventBus) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - invalid phone",
			userID:     "user-1",
			body:       `{"phone":"not-a-phone"}`,
			setup:      func(svc *mocks.MockCoreService, events *mocks.MockEventBus) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "service error",
			userID: "user-1",
			body:   `{"name":"Updated Name"}`,
			setup: func(svc *mocks.MockCoreService, events *mocks.MockEventBus) {
				svc.EXPECT().UpdateProfile(gomock.Any(), "user-1", gomock.Any()).Return(nil, types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, mockEvents, _ := s.setupHandler()
			tt.setup(mockService, mockEvents)

			req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.userID != "" {
				req = testutil.AuthenticatedRequest(req, tt.userID)
			}
			rr := httptest.NewRecorder()

			handler.UpdateProfile(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[*dto.UserDTO]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Equal("Updated Name", resp.Data.Name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ChangePassword
// ---------------------------------------------------------------------------

func (s *CoreHandlerSuite) TestChangePassword() {
	tests := []struct {
		name       string
		userID     string
		body       string
		setup      func(*mocks.MockCoreService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: "user-1",
			body:   `{"old_password":"oldpass123","new_password":"newpass123"}`,
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().ChangePassword(gomock.Any(), "user-1", gomock.Any()).Return(
					&dto.MessageResponse{Message: "Password changed"}, nil,
				)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no user in context",
			userID:     "",
			body:       `{"old_password":"oldpass123","new_password":"newpass123"}`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid JSON",
			userID:     "user-1",
			body:       `{invalid`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - missing old password",
			userID:     "user-1",
			body:       `{"new_password":"newpass123"}`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - same password",
			userID:     "user-1",
			body:       `{"old_password":"samepass1","new_password":"samepass1"}`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "service error",
			userID: "user-1",
			body:   `{"old_password":"oldpass123","new_password":"newpass123"}`,
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().ChangePassword(gomock.Any(), "user-1", gomock.Any()).Return(
					nil, types.NewGoAuthError(types.ErrInvalidCredentials, "wrong password", http.StatusBadRequest),
				)
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodPut, "/change-password", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.userID != "" {
				req = testutil.AuthenticatedRequest(req, tt.userID)
			}
			rr := httptest.NewRecorder()

			handler.ChangePassword(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[*dto.MessageResponse]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Contains(resp.Data.Message, "Password changed")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckEmailAvailability
// ---------------------------------------------------------------------------

func (s *CoreHandlerSuite) TestCheckEmailAvailability() {
	tests := []struct {
		name       string
		body       string
		setup      func(*mocks.MockCoreService)
		wantStatus int
	}{
		{
			name: "success - available",
			body: `{"email":"free@example.com"}`,
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().CheckEmailAvailability(gomock.Any(), "free@example.com").Return(
					&dto.CheckAvailabilityResponse{Available: true, Field: "email"}, nil,
				)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid JSON",
			body:       `{invalid`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - missing email",
			body:       `{}`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - invalid email format",
			body:       `{"email":"not-an-email"}`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "service error",
			body: `{"email":"test@example.com"}`,
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().CheckEmailAvailability(gomock.Any(), "test@example.com").Return(
					nil, types.NewInternalError("db error"),
				)
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodPost, "/availability/email", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.CheckEmailAvailability(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[*dto.CheckAvailabilityResponse]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.True(resp.Data.Available)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckUsernameAvailability
// ---------------------------------------------------------------------------

func (s *CoreHandlerSuite) TestCheckUsernameAvailability() {
	tests := []struct {
		name       string
		body       string
		setup      func(*mocks.MockCoreService)
		wantStatus int
	}{
		{
			name: "success - available",
			body: `{"username":"freeuser"}`,
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().CheckUsernameAvailability(gomock.Any(), "freeuser").Return(
					&dto.CheckAvailabilityResponse{Available: true, Field: "username"}, nil,
				)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid JSON",
			body:       `{invalid`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - missing username",
			body:       `{}`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - invalid username format",
			body:       `{"username":"ab"}`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "service error",
			body: `{"username":"testuser"}`,
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().CheckUsernameAvailability(gomock.Any(), "testuser").Return(
					nil, types.NewInternalError("db error"),
				)
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodPost, "/availability/username", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.CheckUsernameAvailability(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[*dto.CheckAvailabilityResponse]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.True(resp.Data.Available)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckPhoneAvailability
// ---------------------------------------------------------------------------

func (s *CoreHandlerSuite) TestCheckPhoneAvailability() {
	tests := []struct {
		name       string
		body       string
		setup      func(*mocks.MockCoreService)
		wantStatus int
	}{
		{
			name: "success - available",
			body: `{"phone":"+1234567890"}`,
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().CheckPhoneAvailability(gomock.Any(), "+1234567890").Return(
					&dto.CheckAvailabilityResponse{Available: true, Field: "phone"}, nil,
				)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid JSON",
			body:       `{invalid`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - missing phone",
			body:       `{}`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation error - invalid phone format",
			body:       `{"phone":"not-a-phone"}`,
			setup:      func(svc *mocks.MockCoreService) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "service error",
			body: `{"phone":"+1234567890"}`,
			setup: func(svc *mocks.MockCoreService) {
				svc.EXPECT().CheckPhoneAvailability(gomock.Any(), "+1234567890").Return(
					nil, types.NewInternalError("db error"),
				)
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService, _, _ := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodPost, "/availability/phone", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.CheckPhoneAvailability(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[*dto.CheckAvailabilityResponse]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.True(resp.Data.Available)
			}
		})
	}
}

