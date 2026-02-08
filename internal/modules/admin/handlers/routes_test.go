package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/admin/handlers"
	"github.com/bete7512/goauth/internal/modules/admin/handlers/dto"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type AdminHandlerSuite struct {
	suite.Suite
}

func TestAdminHandlerSuite(t *testing.T) {
	suite.Run(t, new(AdminHandlerSuite))
}

func (s *AdminHandlerSuite) setupHandler() (*handlers.AdminHandler, *mocks.MockAdminService) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockService := mocks.NewMockAdminService(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(),
		Logger: mockLogger,
	}

	handler := handlers.NewAdminHandler(deps, mockService)
	return handler, mockService
}

// ---------------------------------------------------------------------------
// ListUsers
// ---------------------------------------------------------------------------

func (s *AdminHandlerSuite) TestListUsers() {
	user1 := testutil.TestUser()
	user2 := testutil.TestUser()
	user2.Email = "other@example.com"

	tests := []struct {
		name       string
		query      string
		setup      func(*mocks.MockAdminService)
		wantStatus int
		wantTotal  int64
	}{
		{
			name: "success with results",
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().ListUsers(gomock.Any(), gomock.Any()).Return([]*models.User{user1, user2}, int64(2), nil)
			},
			wantStatus: http.StatusOK,
			wantTotal:  2,
		},
		{
			name: "success with empty list",
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().ListUsers(gomock.Any(), gomock.Any()).Return([]*models.User{}, int64(0), nil)
			},
			wantStatus: http.StatusOK,
			wantTotal:  0,
		},
		{
			name:  "query param forwarded",
			query: "?query=john",
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().ListUsers(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ interface{}, opts models.UserListOpts) ([]*models.User, int64, *types.GoAuthError) {
						s.Equal("john", opts.Query)
						return []*models.User{}, int64(0), nil
					},
				)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "service error",
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().ListUsers(gomock.Any(), gomock.Any()).Return(nil, int64(0), types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/admin/users"+tt.query, nil)
			rr := httptest.NewRecorder()

			handler.ListUsers(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[types.ListResponse[*dto.AdminUserDTO]]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Equal(tt.wantTotal, resp.Data.Total)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func (s *AdminHandlerSuite) TestGetUser() {
	user := testutil.TestUser()

	tests := []struct {
		name       string
		userID     string
		setup      func(*mocks.MockAdminService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: user.ID,
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().GetUser(gomock.Any(), user.ID).Return(user, nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "not found",
			userID: "nonexistent",
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().GetUser(gomock.Any(), "nonexistent").Return(nil, types.NewUserNotFoundError())
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/admin/users/"+tt.userID, nil)
			req.SetPathValue("id", tt.userID)
			rr := httptest.NewRecorder()

			handler.GetUser(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[*dto.AdminUserDTO]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Equal(user.ID, resp.Data.ID)
				s.Equal(user.Email, resp.Data.Email)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateUser
// ---------------------------------------------------------------------------

func (s *AdminHandlerSuite) TestUpdateUser() {
	user := testutil.TestUser()

	tests := []struct {
		name       string
		userID     string
		body       string
		setup      func(*mocks.MockAdminService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: user.ID,
			body:   `{"name": "Updated Name"}`,
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().GetUser(gomock.Any(), user.ID).Return(user, nil)
				svc.EXPECT().UpdateUser(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "user not found",
			userID: "nonexistent",
			body:   `{"name": "Updated Name"}`,
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().GetUser(gomock.Any(), "nonexistent").Return(nil, types.NewUserNotFoundError())
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:   "invalid JSON body",
			userID: user.ID,
			body:   `{invalid`,
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().GetUser(gomock.Any(), user.ID).Return(user, nil)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "validation error - empty request",
			userID: user.ID,
			body:   `{}`,
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().GetUser(gomock.Any(), user.ID).Return(user, nil)
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "service update error",
			userID: user.ID,
			body:   `{"name": "Updated Name"}`,
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().GetUser(gomock.Any(), user.ID).Return(user, nil)
				svc.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodPut, "/admin/users/"+tt.userID, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.userID)
			rr := httptest.NewRecorder()

			handler.UpdateUser(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// DeleteUser
// ---------------------------------------------------------------------------

func (s *AdminHandlerSuite) TestDeleteUser() {
	tests := []struct {
		name       string
		userID     string
		setup      func(*mocks.MockAdminService)
		wantStatus int
	}{
		{
			name:   "success",
			userID: "user-123",
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().DeleteUser(gomock.Any(), "user-123").Return(nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "service error",
			userID: "user-123",
			setup: func(svc *mocks.MockAdminService) {
				svc.EXPECT().DeleteUser(gomock.Any(), "user-123").Return(types.NewInternalError("db error"))
			},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler()
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodDelete, "/admin/users/"+tt.userID, nil)
			req.SetPathValue("id", tt.userID)
			rr := httptest.NewRecorder()

			handler.DeleteUser(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				var resp types.APIResponse[dto.MessageResponse]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Contains(resp.Data.Message, "deleted")
			}
		})
	}
}
