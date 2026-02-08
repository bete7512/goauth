package core_services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type ProfileServiceSuite struct {
	suite.Suite
}

func TestProfileServiceSuite(t *testing.T) {
	suite.Run(t, new(ProfileServiceSuite))
}

func (s *ProfileServiceSuite) setupService() (
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

// ---------------------------------------------------------------------------
// GetProfile
// ---------------------------------------------------------------------------

func (s *ProfileServiceSuite) TestGetProfile() {
	tests := []struct {
		name       string
		overrideID string
		setup      func(*models.User, *mocks.MockUserRepository)
		wantErr    bool
		errCode    types.ErrorCode
	}{
		{
			name: "success",
			setup: func(u *models.User, ur *mocks.MockUserRepository) {
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

			resp, goauthErr := svc.GetProfile(context.Background(), userID)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
				s.Equal(testUser.ID, resp.ID)
				s.Equal(testUser.Email, resp.Email)
				s.Equal(testUser.Name, resp.Name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateProfile
// ---------------------------------------------------------------------------

func (s *ProfileServiceSuite) TestUpdateProfile() {
	tests := []struct {
		name       string
		overrideID string
		req        *dto.UpdateProfileRequest
		setup      func(*models.User, *mocks.MockUserRepository)
		wantErr    bool
		errCode    types.ErrorCode
		wantName   string
		wantPhone  string
		wantAvatar string
	}{
		{
			name: "update name",
			req:  &dto.UpdateProfileRequest{Name: "Updated Name"},
			setup: func(u *models.User, ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
			},
			wantName: "Updated Name",
		},
		{
			name: "update phone",
			req:  &dto.UpdateProfileRequest{Phone: "+9876543210"},
			setup: func(u *models.User, ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
			},
			wantPhone: "+9876543210",
		},
		{
			name: "update avatar",
			req:  &dto.UpdateProfileRequest{Avatar: "https://example.com/new-avatar.png"},
			setup: func(u *models.User, ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
			},
			wantAvatar: "https://example.com/new-avatar.png",
		},
		{
			name: "update multiple fields",
			req:  &dto.UpdateProfileRequest{Name: "New Name", Phone: "+1111111111", Avatar: "https://example.com/avatar.png"},
			setup: func(u *models.User, ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
			},
			wantName:   "New Name",
			wantPhone:  "+1111111111",
			wantAvatar: "https://example.com/avatar.png",
		},
		{
			name:       "user not found",
			overrideID: "nonexistent",
			req:        &dto.UpdateProfileRequest{Name: "Updated Name"},
			setup: func(_ *models.User, ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), "nonexistent").Return(nil, errors.New("not found"))
			},
			wantErr: true,
			errCode: types.ErrUserNotFound,
		},
		{
			name: "db update fails",
			req:  &dto.UpdateProfileRequest{Name: "Updated Name"},
			setup: func(u *models.User, ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(errors.New("db error"))
			},
			wantErr: true,
			errCode: types.ErrInternalError,
		},
		{
			name: "empty fields not overwritten",
			req:  &dto.UpdateProfileRequest{Name: "Only Name"},
			setup: func(u *models.User, ur *mocks.MockUserRepository) {
				u.PhoneNumber = "+original"
				u.Avatar = "https://example.com/original.png"
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
				ur.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, user *models.User) error {
						s.Equal("Only Name", user.Name)
						s.Equal("+original", user.PhoneNumber, "phone should not be overwritten")
						s.Equal("https://example.com/original.png", user.Avatar, "avatar should not be overwritten")
						return nil
					},
				)
			},
			wantName: "Only Name",
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

			resp, goauthErr := svc.UpdateProfile(context.Background(), userID, tt.req)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
				s.Equal(testUser.ID, resp.ID)
				if tt.wantName != "" {
					s.Equal(tt.wantName, resp.Name)
				}
				if tt.wantPhone != "" {
					s.Equal(tt.wantPhone, resp.PhoneNumber)
				}
				if tt.wantAvatar != "" {
					s.Equal(tt.wantAvatar, resp.Avatar)
				}
				s.NotNil(resp.UpdatedAt, "UpdatedAt should be set")
			}
		})
	}
}
