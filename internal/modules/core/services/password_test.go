package core_services_test

import (
	"context"
	"errors"
	"testing"
	"time"

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

type PasswordServiceSuite struct {
	suite.Suite
}

func TestPasswordServiceSuite(t *testing.T) {
	suite.Run(t, new(PasswordServiceSuite))
}

func (s *PasswordServiceSuite) setupService() (
	core_services.CoreService,
	*mocks.MockUserRepository,
	*mocks.MockTokenRepository,
	*mocks.MockEventBus,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenRepo := mocks.NewMockTokenRepository(ctrl)
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

	svc := core_services.NewCoreService(deps, mockUserRepo, mockExtAttrRepo, mockTokenRepo, mockLogger, secMgr, cfg)
	return svc, mockUserRepo, mockTokenRepo, mockEvents
}

func (s *PasswordServiceSuite) TestChangePassword() {
	tests := []struct {
		name       string
		req        *dto.ChangePasswordRequest
		setup      func(*models.User, *mocks.MockUserRepository, *mocks.MockEventBus)
		overrideID string
		wantErr    bool
		errCode    types.ErrorCode
		statusCode int
		wantMsg    string
	}{
		{
			name: "success",
			req:  &dto.ChangePasswordRequest{OldPassword: "password123", NewPassword: "newpassword456"},
			setup: func(u *models.User, ur *mocks.MockUserRepository, ev *mocks.MockEventBus) {
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventAfterChangePassword, gomock.AssignableToTypeOf(&types.PasswordChangedData{})).Return(nil)
			},
			wantMsg: "Password changed successfully",
		},
		{
			name:       "user not found",
			overrideID: "nonexistent",
			req:        &dto.ChangePasswordRequest{OldPassword: "password123", NewPassword: "newpassword456"},
			setup: func(_ *models.User, ur *mocks.MockUserRepository, _ *mocks.MockEventBus) {
				ur.EXPECT().FindByID(gomock.Any(), "nonexistent").Return(nil, errors.New("not found"))
			},
			wantErr:    true,
			errCode:    types.ErrUserNotFound,
			statusCode: 404,
		},
		{
			name: "wrong old password",
			req:  &dto.ChangePasswordRequest{OldPassword: "wrongpassword", NewPassword: "newpassword456"},
			setup: func(u *models.User, ur *mocks.MockUserRepository, _ *mocks.MockEventBus) {
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
			},
			wantErr:    true,
			errCode:    types.ErrInvalidCredentials,
			statusCode: 401,
		},
		{
			name: "db update fails",
			req:  &dto.ChangePasswordRequest{OldPassword: "password123", NewPassword: "newpassword456"},
			setup: func(u *models.User, ur *mocks.MockUserRepository, _ *mocks.MockEventBus) {
				ur.EXPECT().FindByID(gomock.Any(), u.ID).Return(u, nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(errors.New("db error"))
			},
			wantErr:    true,
			errCode:    types.ErrInternalError,
			statusCode: 500,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			testUser := testutil.TestUser()
			svc, mockUserRepo, _, mockEvents := s.setupService()
			tt.setup(testUser, mockUserRepo, mockEvents)

			userID := testUser.ID
			if tt.overrideID != "" {
				userID = tt.overrideID
			}

			resp, goauthErr := svc.ChangePassword(context.Background(), userID, tt.req)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
				s.Equal(tt.statusCode, goauthErr.StatusCode)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
				if tt.wantMsg != "" {
					s.Equal(tt.wantMsg, resp.Message)
				}
			}
		})
	}
}

func (s *PasswordServiceSuite) TestForgotPassword() {
	testUser := testutil.TestUser()

	tests := []struct {
		name       string
		req        *dto.ForgotPasswordRequest
		setup      func(*mocks.MockUserRepository, *mocks.MockTokenRepository, *mocks.MockEventBus)
		wantErr    bool
		errCode    types.ErrorCode
		statusCode int
	}{
		{
			name: "success",
			req:  &dto.ForgotPasswordRequest{Email: testUser.Email},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus) {
				ur.EXPECT().FindByEmail(gomock.Any(), testUser.Email).Return(testUser, nil)
				tr.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventSendPasswordResetEmail, gomock.AssignableToTypeOf(&types.PasswordResetRequestData{})).Return(nil)
			},
		},
		{
			name: "user not found - does not reveal",
			req:  &dto.ForgotPasswordRequest{Email: "unknown@example.com"},
			setup: func(ur *mocks.MockUserRepository, _ *mocks.MockTokenRepository, _ *mocks.MockEventBus) {
				ur.EXPECT().FindByEmail(gomock.Any(), "unknown@example.com").Return(nil, errors.New("not found"))
			},
			wantErr: false,
		},
		{
			name:       "empty email",
			req:        &dto.ForgotPasswordRequest{Email: ""},
			setup:      func(_ *mocks.MockUserRepository, _ *mocks.MockTokenRepository, _ *mocks.MockEventBus) {},
			wantErr:    true,
			errCode:    types.ErrInvalidRequestBody,
			statusCode: 400,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, mockTokenRepo, mockEvents := s.setupService()
			tt.setup(mockUserRepo, mockTokenRepo, mockEvents)

			resp, goauthErr := svc.ForgotPassword(context.Background(), tt.req)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
				s.Equal(tt.statusCode, goauthErr.StatusCode)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
			}
		})
	}
}

func (s *PasswordServiceSuite) TestResetPassword() {
	testUser := testutil.TestUser()
	validToken := testutil.TestVerificationToken(testUser.ID, models.TokenTypePasswordReset)
	expiredToken := testutil.TestExpiredVerificationToken(testUser.ID, models.TokenTypePasswordReset)

	tests := []struct {
		name    string
		req     *dto.ResetPasswordRequest
		setup   func(*mocks.MockUserRepository, *mocks.MockTokenRepository, *mocks.MockEventBus)
		wantErr bool
		errCode types.ErrorCode
	}{
		{
			name: "success with token",
			req:  &dto.ResetPasswordRequest{Token: validToken.Token, NewPassword: "newpassword456"},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus) {
				tr.EXPECT().FindByToken(gomock.Any(), validToken.Token).Return(validToken, nil)
				ur.EXPECT().FindByID(gomock.Any(), testUser.ID).Return(testUser, nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
				tr.EXPECT().MarkAsUsed(gomock.Any(), validToken.ID).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventAfterResetPassword, gomock.AssignableToTypeOf(&types.PasswordChangedData{})).Return(nil)
			},
		},
		{
			name: "invalid token",
			req:  &dto.ResetPasswordRequest{Token: "invalid-token", NewPassword: "newpassword456"},
			setup: func(_ *mocks.MockUserRepository, tr *mocks.MockTokenRepository, _ *mocks.MockEventBus) {
				tr.EXPECT().FindByToken(gomock.Any(), "invalid-token").Return(nil, errors.New("not found"))
			},
			wantErr: true,
			errCode: types.ErrInvalidToken,
		},
		{
			name: "expired token",
			req:  &dto.ResetPasswordRequest{Token: expiredToken.Token, NewPassword: "newpassword456"},
			setup: func(_ *mocks.MockUserRepository, tr *mocks.MockTokenRepository, _ *mocks.MockEventBus) {
				tr.EXPECT().FindByToken(gomock.Any(), expiredToken.Token).Return(expiredToken, nil)
			},
			wantErr: true,
			errCode: types.ErrTokenExpired,
		},
		{
			name:    "missing token and code",
			req:     &dto.ResetPasswordRequest{NewPassword: "newpassword456"},
			setup:   func(_ *mocks.MockUserRepository, _ *mocks.MockTokenRepository, _ *mocks.MockEventBus) {},
			wantErr: true,
			errCode: types.ErrInvalidRequestBody,
		},
		{
			name: "user not found after valid token",
			req:  &dto.ResetPasswordRequest{Token: "orphan-token", NewPassword: "newpassword456"},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, _ *mocks.MockEventBus) {
				tok := &models.Token{
					ID:        "tok-orphan",
					UserID:    "deleted-user",
					Token:     "orphan-token",
					Type:      models.TokenTypePasswordReset,
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CreatedAt: time.Now(),
				}
				tr.EXPECT().FindByToken(gomock.Any(), "orphan-token").Return(tok, nil)
				ur.EXPECT().FindByID(gomock.Any(), "deleted-user").Return(nil, errors.New("not found"))
			},
			wantErr: true,
			errCode: types.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, mockTokenRepo, mockEvents := s.setupService()
			tt.setup(mockUserRepo, mockTokenRepo, mockEvents)

			resp, goauthErr := svc.ResetPassword(context.Background(), tt.req)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
			}
		})
	}
}
