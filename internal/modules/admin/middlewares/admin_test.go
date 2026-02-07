package middlewares_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/admin/middlewares"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type AdminAuthMiddlewareSuite struct {
	suite.Suite
}

func TestAdminAuthMiddlewareSuite(t *testing.T) {
	suite.Run(t, new(AdminAuthMiddlewareSuite))
}

func (s *AdminAuthMiddlewareSuite) okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the admin user was set in context
		user, ok := r.Context().Value(types.UserKey).(*models.User)
		if ok && user != nil {
			w.Header().Set("X-Admin-ID", user.ID)
		}
		w.WriteHeader(http.StatusOK)
	})
}

func (s *AdminAuthMiddlewareSuite) setupMiddleware(
	ctrl *gomock.Controller,
) (func(http.Handler) http.Handler, *mocks.MockStorage, *mocks.MockCoreStorage, *mocks.MockUserRepository) {
	mockStorage := mocks.NewMockStorage(ctrl)
	mockCoreStorage := mocks.NewMockCoreStorage(ctrl)
	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	deps := config.ModuleDependencies{
		Config:  testutil.TestConfig(),
		Storage: mockStorage,
		Logger:  mockLogger,
	}

	mw := middlewares.NewAdminAuthMiddleware(deps)
	return mw.Middleware, mockStorage, mockCoreStorage, mockUserRepo
}

func (s *AdminAuthMiddlewareSuite) TestAdminAuth() {
	adminUser := testutil.TestAdminUser()
	regularUser := testutil.TestUser()
	regularUser.IsSuperAdmin = false

	tests := []struct {
		name       string
		userID     string // empty = no user ID in context
		setup      func(*mocks.MockStorage, *mocks.MockCoreStorage, *mocks.MockUserRepository)
		wantStatus int
		wantErrCode string
	}{
		{
			name:   "success - super admin",
			userID: adminUser.ID,
			setup: func(st *mocks.MockStorage, cs *mocks.MockCoreStorage, ur *mocks.MockUserRepository) {
				st.EXPECT().Core().Return(cs)
				cs.EXPECT().Users().Return(ur)
				ur.EXPECT().FindByID(gomock.Any(), adminUser.ID).Return(adminUser, nil)
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "no user ID in context",
			userID: "",
			setup: func(st *mocks.MockStorage, cs *mocks.MockCoreStorage, ur *mocks.MockUserRepository) {
				// No calls expected
			},
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: string(types.ErrUnauthorized),
		},
		{
			name:   "user not found in DB",
			userID: "nonexistent",
			setup: func(st *mocks.MockStorage, cs *mocks.MockCoreStorage, ur *mocks.MockUserRepository) {
				st.EXPECT().Core().Return(cs)
				cs.EXPECT().Users().Return(ur)
				ur.EXPECT().FindByID(gomock.Any(), "nonexistent").Return(nil, errors.New("not found"))
			},
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: string(types.ErrUnauthorized),
		},
		{
			name:   "user is not super admin",
			userID: regularUser.ID,
			setup: func(st *mocks.MockStorage, cs *mocks.MockCoreStorage, ur *mocks.MockUserRepository) {
				st.EXPECT().Core().Return(cs)
				cs.EXPECT().Users().Return(ur)
				ur.EXPECT().FindByID(gomock.Any(), regularUser.ID).Return(regularUser, nil)
			},
			wantStatus:  http.StatusForbidden,
			wantErrCode: string(types.ErrForbidden),
		},
		{
			name:   "core storage unavailable",
			userID: adminUser.ID,
			setup: func(st *mocks.MockStorage, cs *mocks.MockCoreStorage, ur *mocks.MockUserRepository) {
				st.EXPECT().Core().Return(nil)
			},
			wantStatus:  http.StatusInternalServerError,
			wantErrCode: string(types.ErrInternalError),
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			ctrl := gomock.NewController(s.T())
			s.T().Cleanup(ctrl.Finish)

			mw, mockStorage, mockCoreStorage, mockUserRepo := s.setupMiddleware(ctrl)
			tt.setup(mockStorage, mockCoreStorage, mockUserRepo)

			req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
			if tt.userID != "" {
				req = testutil.AuthenticatedRequest(req, tt.userID)
			}
			rr := httptest.NewRecorder()

			mw(s.okHandler()).ServeHTTP(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantStatus == http.StatusOK {
				// Verify admin user was set in context (okHandler writes it as header)
				s.Equal(adminUser.ID, rr.Header().Get("X-Admin-ID"))
			}

			if tt.wantErrCode != "" {
				var resp map[string]interface{}
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				data, ok := resp["data"].(map[string]interface{})
				s.True(ok)
				s.Equal(tt.wantErrCode, data["code"])
			}
		})
	}
}
