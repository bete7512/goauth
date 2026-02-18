package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/mocks"
	magiclink_dto "github.com/bete7512/goauth/internal/modules/magiclink/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/magiclink/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type MagicLinkServiceSuite struct {
	suite.Suite
}

func TestMagicLinkServiceSuite(t *testing.T) {
	suite.Run(t, new(MagicLinkServiceSuite))
}

func (s *MagicLinkServiceSuite) setupService(cfgOverride ...*config.MagicLinkModuleConfig) (
	services.MagicLinkService,
	*mocks.MockUserRepository,
	*mocks.MockTokenRepository,
	*mocks.MockEventBus,
	*mocks.MockLogger,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenRepo := mocks.NewMockTokenRepository(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	secMgr := testutil.TestSecurityManager()

	cfg := &config.MagicLinkModuleConfig{
		TokenExpiry:  15 * time.Minute,
		AutoRegister: false,
	}
	if len(cfgOverride) > 0 {
		cfg = cfgOverride[0]
	}

	testCfg := testutil.TestConfig()
	testCfg.APIURL = "http://localhost:8080"

	deps := config.ModuleDependencies{
		Config:          testCfg,
		Events:          mockEvents,
		Logger:          mockLogger,
		SecurityManager: secMgr,
	}

	svc := services.NewMagicLinkService(deps, mockUserRepo, mockTokenRepo, secMgr, cfg)
	return svc, mockUserRepo, mockTokenRepo, mockEvents, mockLogger
}

func (s *MagicLinkServiceSuite) TestSendMagicLink() {
	tests := []struct {
		name    string
		req     *magiclink_dto.MagicLinkSendRequest
		cfg     *config.MagicLinkModuleConfig
		setup   func(*mocks.MockUserRepository, *mocks.MockTokenRepository, *mocks.MockEventBus, *mocks.MockLogger)
		wantErr bool
		wantMsg string
	}{
		{
			name: "success - user exists",
			req:  &magiclink_dto.MagicLinkSendRequest{Email: "test@example.com"},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				ur.EXPECT().FindByEmail(gomock.Any(), "test@example.com").Return(testutil.TestUser(), nil)
				tr.EXPECT().FindByEmailAndType(gomock.Any(), "test@example.com", models.TokenTypeMagicLink).Return(nil, errors.New("not found"))
				tr.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventSendMagicLink, gomock.Any()).Return(nil)
			},
			wantMsg: "If an account exists, a magic link has been sent",
		},
		{
			name: "user not found - no auto register",
			req:  &magiclink_dto.MagicLinkSendRequest{Email: "unknown@example.com"},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				ur.EXPECT().FindByEmail(gomock.Any(), "unknown@example.com").Return(nil, errors.New("not found"))
			},
			wantMsg: "If an account exists, a magic link has been sent",
		},
		{
			name: "user not found - auto register enabled",
			req:  &magiclink_dto.MagicLinkSendRequest{Email: "new@example.com"},
			cfg: &config.MagicLinkModuleConfig{
				TokenExpiry:  15 * time.Minute,
				AutoRegister: true,
			},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				ur.EXPECT().FindByEmail(gomock.Any(), "new@example.com").Return(nil, errors.New("not found"))
				ur.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
				lg.EXPECT().Infof(gomock.Any(), gomock.Any()).AnyTimes()
				tr.EXPECT().FindByEmailAndType(gomock.Any(), "new@example.com", models.TokenTypeMagicLink).Return(nil, errors.New("not found"))
				tr.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventSendMagicLink, gomock.Any()).Return(nil)
			},
			wantMsg: "If an account exists, a magic link has been sent",
		},
		{
			name: "deletes existing token before creating new one",
			req:  &magiclink_dto.MagicLinkSendRequest{Email: "test@example.com"},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				user := testutil.TestUser()
				existingToken := testutil.TestToken(user.ID, models.TokenTypeMagicLink)
				existingToken.Email = "test@example.com"

				ur.EXPECT().FindByEmail(gomock.Any(), "test@example.com").Return(user, nil)
				tr.EXPECT().FindByEmailAndType(gomock.Any(), "test@example.com", models.TokenTypeMagicLink).Return(existingToken, nil)
				tr.EXPECT().DeleteByIDAndType(gomock.Any(), existingToken.ID, models.TokenTypeMagicLink).Return(nil)
				tr.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventSendMagicLink, gomock.Any()).Return(nil)
			},
			wantMsg: "If an account exists, a magic link has been sent",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			var svc services.MagicLinkService
			var mockUserRepo *mocks.MockUserRepository
			var mockTokenRepo *mocks.MockTokenRepository
			var mockEvents *mocks.MockEventBus
			var mockLogger *mocks.MockLogger

			if tt.cfg != nil {
				svc, mockUserRepo, mockTokenRepo, mockEvents, mockLogger = s.setupService(tt.cfg)
			} else {
				svc, mockUserRepo, mockTokenRepo, mockEvents, mockLogger = s.setupService()
			}
			tt.setup(mockUserRepo, mockTokenRepo, mockEvents, mockLogger)

			resp, authErr := svc.SendMagicLink(context.Background(), tt.req)

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(resp)
			} else {
				s.Nil(authErr)
				s.NotNil(resp)
				if tt.wantMsg != "" {
					s.Equal(tt.wantMsg, resp.Message)
				}
			}
		})
	}
}

func (s *MagicLinkServiceSuite) TestVerifyMagicLink() {
	tests := []struct {
		name    string
		token   string
		setup   func(*mocks.MockUserRepository, *mocks.MockTokenRepository, *mocks.MockEventBus, *mocks.MockLogger)
		wantErr bool
		errCode types.ErrorCode
	}{
		{
			name:  "success",
			token: "valid-token",
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				user := testutil.TestUser()
				token := testutil.TestVerificationToken(user.ID, models.TokenTypeMagicLink)
				token.Token = "valid-token"

				tr.EXPECT().FindByToken(gomock.Any(), "valid-token").Return(token, nil)
				ur.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				tr.EXPECT().MarkAsUsed(gomock.Any(), token.ID).Return(nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventAfterMagicLinkVerified, gomock.Any()).Return(nil)
			},
		},
		{
			name:  "invalid token",
			token: "bad-token",
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				tr.EXPECT().FindByToken(gomock.Any(), "bad-token").Return(nil, errors.New("not found"))
			},
			wantErr: true,
			errCode: types.ErrInvalidToken,
		},
		{
			name:  "expired token",
			token: "expired-token",
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				user := testutil.TestUser()
				token := testutil.TestExpiredVerificationToken(user.ID, models.TokenTypeMagicLink)
				token.Token = "expired-token"

				tr.EXPECT().FindByToken(gomock.Any(), "expired-token").Return(token, nil)
			},
			wantErr: true,
			errCode: types.ErrTokenExpired,
		},
		{
			name:  "already used token",
			token: "used-token",
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				user := testutil.TestUser()
				token := testutil.TestVerificationToken(user.ID, models.TokenTypeMagicLink)
				token.Token = "used-token"
				token.Used = true

				tr.EXPECT().FindByToken(gomock.Any(), "used-token").Return(token, nil)
			},
			wantErr: true,
			errCode: types.ErrInvalidToken,
		},
		{
			name:  "user not found",
			token: "orphan-token",
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				token := testutil.TestVerificationToken("nonexistent-user", models.TokenTypeMagicLink)
				token.Token = "orphan-token"

				tr.EXPECT().FindByToken(gomock.Any(), "orphan-token").Return(token, nil)
				ur.EXPECT().FindByID(gomock.Any(), "nonexistent-user").Return(nil, errors.New("not found"))
			},
			wantErr: true,
			errCode: types.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, mockTokenRepo, mockEvents, mockLogger := s.setupService()
			tt.setup(mockUserRepo, mockTokenRepo, mockEvents, mockLogger)

			resp, authErr := svc.VerifyMagicLink(context.Background(), tt.token)

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(resp)
				s.Equal(tt.errCode, authErr.Code)
			} else {
				s.Nil(authErr)
				s.NotNil(resp)
				s.NotNil(resp.AccessToken)
				s.NotNil(resp.RefreshToken)
				s.NotNil(resp.User)
				s.Equal("Magic link verified successfully", resp.Message)
			}
		})
	}
}

func (s *MagicLinkServiceSuite) TestVerifyByCode() {
	tests := []struct {
		name    string
		req     *magiclink_dto.MagicLinkVerifyByCodeRequest
		setup   func(*mocks.MockUserRepository, *mocks.MockTokenRepository, *mocks.MockEventBus, *mocks.MockLogger)
		wantErr bool
		errCode types.ErrorCode
	}{
		{
			name: "success",
			req:  &magiclink_dto.MagicLinkVerifyByCodeRequest{Email: "test@example.com", Code: "123456"},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				user := testutil.TestUser()
				token := testutil.TestVerificationToken(user.ID, models.TokenTypeMagicLink)

				tr.EXPECT().FindByCode(gomock.Any(), "123456", models.TokenTypeMagicLink).Return(token, nil)
				ur.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				tr.EXPECT().MarkAsUsed(gomock.Any(), token.ID).Return(nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventAfterMagicLinkVerified, gomock.Any()).Return(nil)
			},
		},
		{
			name: "invalid code",
			req:  &magiclink_dto.MagicLinkVerifyByCodeRequest{Email: "test@example.com", Code: "000000"},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				tr.EXPECT().FindByCode(gomock.Any(), "000000", models.TokenTypeMagicLink).Return(nil, errors.New("not found"))
			},
			wantErr: true,
			errCode: types.ErrInvalidToken,
		},
		{
			name: "email mismatch",
			req:  &magiclink_dto.MagicLinkVerifyByCodeRequest{Email: "wrong@example.com", Code: "123456"},
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository, ev *mocks.MockEventBus, lg *mocks.MockLogger) {
				user := testutil.TestUser()
				token := testutil.TestVerificationToken(user.ID, models.TokenTypeMagicLink)
				// token.Email is "test@example.com", but request has "wrong@example.com"

				tr.EXPECT().FindByCode(gomock.Any(), "123456", models.TokenTypeMagicLink).Return(token, nil)
			},
			wantErr: true,
			errCode: types.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, mockTokenRepo, mockEvents, mockLogger := s.setupService()
			tt.setup(mockUserRepo, mockTokenRepo, mockEvents, mockLogger)

			resp, authErr := svc.VerifyByCode(context.Background(), tt.req)

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(resp)
				s.Equal(tt.errCode, authErr.Code)
			} else {
				s.Nil(authErr)
				s.NotNil(resp)
				s.NotNil(resp.AccessToken)
				s.NotNil(resp.RefreshToken)
				s.NotNil(resp.User)
			}
		})
	}
}
