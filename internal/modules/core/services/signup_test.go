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

type SignupServiceSuite struct {
	suite.Suite
}

func TestSignupServiceSuite(t *testing.T) {
	suite.Run(t, new(SignupServiceSuite))
}

func (s *SignupServiceSuite) setupService(cfgOverride ...*config.CoreConfig) (
	*core_services.CoreService,
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
	if len(cfgOverride) > 0 {
		cfg = cfgOverride[0]
	}

	deps := config.ModuleDependencies{
		Config:          testutil.TestConfig(),
		Events:          mockEvents,
		Logger:          mockLogger,
		SecurityManager: secMgr,
	}

	svc := core_services.NewCoreService(deps, mockUserRepo, mockExtAttrRepo, mockTokenRepo, mockVerifRepo, mockLogger, secMgr, cfg)
	return svc, mockUserRepo
}

func (s *SignupServiceSuite) TestSignup() {
	tests := []struct {
		name      string
		req       *dto.SignupRequest
		cfg       *config.CoreConfig
		setup     func(*mocks.MockUserRepository)
		wantErr   bool
		errCode   types.ErrorCode
		wantEmail string
		wantMsg   string
	}{
		{
			name: "success",
			req:  &dto.SignupRequest{Email: "new@example.com", Password: "password123", Name: "New User"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, errors.New("not found"))
				ur.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
			},
			wantEmail: "new@example.com",
		},
		{
			name: "email already exists",
			req:  &dto.SignupRequest{Email: "taken@example.com", Password: "password123"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByEmail(gomock.Any(), "taken@example.com").Return(testutil.TestUser(), nil)
			},
			wantErr: true,
			errCode: types.ErrUserAlreadyExists,
		},
		{
			name: "username already exists",
			req:  &dto.SignupRequest{Email: "new@example.com", Username: "takenuser", Password: "password123"},
			cfg:  &config.CoreConfig{RequireUserName: true},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, errors.New("not found"))
				ur.EXPECT().FindByUsername(gomock.Any(), "takenuser").Return(testutil.TestUser(), nil)
			},
			wantErr: true,
			errCode: types.ErrUsernameAlreadyExists,
		},
		{
			name: "phone already in use",
			req:  &dto.SignupRequest{Email: "new@example.com", PhoneNumber: "+1234567890", Password: "password123"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, errors.New("not found"))
				ur.EXPECT().FindByPhoneNumber(gomock.Any(), "+1234567890").Return(testutil.TestUser(), nil)
			},
			wantErr: true,
			errCode: types.ErrPhoneAlreadyInUse,
		},
		{
			name: "create user db error",
			req:  &dto.SignupRequest{Email: "new@example.com", Password: "password123"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, errors.New("not found"))
				ur.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(errors.New("db error"))
			},
			wantErr: true,
			errCode: types.ErrInternalError,
		},
		{
			name: "with email verification required - user created inactive",
			req:  &dto.SignupRequest{Email: "new@example.com", Password: "password123"},
			cfg:  &config.CoreConfig{RequireEmailVerification: true},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, errors.New("not found"))
				ur.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).DoAndReturn(
					func(_ context.Context, user *models.User) error {
						s.False(user.Active, "user should be inactive when email verification required")
						s.False(user.EmailVerified, "email should not be verified")
						return nil
					},
				)
			},
			wantMsg: "verify your email",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			var svc *core_services.CoreService
			var mockUserRepo *mocks.MockUserRepository

			if tt.cfg != nil {
				svc, mockUserRepo = s.setupService(tt.cfg)
			} else {
				svc, mockUserRepo = s.setupService()
			}
			tt.setup(mockUserRepo)

			resp, goauthErr := svc.Signup(context.Background(), tt.req)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
				s.NotNil(resp.User)
				if tt.wantEmail != "" {
					s.Equal(tt.wantEmail, resp.User.Email)
				}
				if tt.wantMsg != "" {
					s.Contains(resp.Message, tt.wantMsg)
				}
			}
		})
	}
}
