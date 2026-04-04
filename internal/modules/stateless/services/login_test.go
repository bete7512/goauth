package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/stateless/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type StatelessLoginSuite struct {
	suite.Suite
}

func TestStatelessLoginSuite(t *testing.T) {
	suite.Run(t, new(StatelessLoginSuite))
}

func (s *StatelessLoginSuite) setupService() (
	*services.StatelessService,
	*mocks.MockUserRepository,
	*mocks.MockTokenRepository,
	*mocks.MockLogger,
	*mocks.MockEventBus,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenRepo := mocks.NewMockTokenRepository(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)

	secMgr := testutil.TestSecurityManager()
	cfg := &config.StatelessModuleConfig{RefreshTokenRotation: true}

	deps := config.ModuleDependencies{
		Config:           testutil.TestConfig(),
		Events:           mockEvents,
		Logger:           mockLogger,
		SecurityManager:  secMgr,
		AuthInterceptors: interceptor.NewRegistry(),
	}

	svc := services.NewStatelessService(deps, mockUserRepo, mockTokenRepo, mockLogger, secMgr, cfg)
	return svc, mockUserRepo, mockTokenRepo, mockLogger, mockEvents
}

func (s *StatelessLoginSuite) TestLogin_Success() {
	svc, mockUserRepo, mockTokenRepo, mockLogger, _ := s.setupService()
	user := testutil.TestUser()

	mockUserRepo.EXPECT().FindByEmail(gomock.Any(), user.Email).Return(user, nil)
	mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(nil)
	mockUserRepo.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
	_ = mockLogger

	req := &dto.LoginRequest{Email: user.Email, Password: "password123"}
	resp, authErr := svc.Login(context.Background(), req)

	s.Nil(authErr)
	s.NotNil(resp.AccessToken)
	s.NotNil(resp.RefreshToken)
	s.NotNil(resp.User)
	s.Equal(user.Email, resp.User.Email)
}

func (s *StatelessLoginSuite) TestLogin_SuccessWithUsername() {
	svc, mockUserRepo, mockTokenRepo, _, _ := s.setupService()
	user := testutil.TestUser()

	// First try email (empty), fail, then try username
	mockUserRepo.EXPECT().FindByEmail(gomock.Any(), "").Return(nil, models.ErrNotFound)
	mockUserRepo.EXPECT().FindByUsername(gomock.Any(), user.Username).Return(user, nil)
	mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(nil)
	mockUserRepo.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)

	req := &dto.LoginRequest{Username: user.Username, Password: "password123"}
	resp, authErr := svc.Login(context.Background(), req)

	s.Nil(authErr)
	s.NotNil(resp.AccessToken)
}

func (s *StatelessLoginSuite) TestLogin_UserNotFound() {
	svc, mockUserRepo, _, _, _ := s.setupService()

	mockUserRepo.EXPECT().FindByEmail(gomock.Any(), "unknown@example.com").Return(nil, models.ErrNotFound)

	req := &dto.LoginRequest{Email: "unknown@example.com", Password: "password123"}
	_, authErr := svc.Login(context.Background(), req)

	s.NotNil(authErr)
	s.Equal(types.ErrInvalidCredentials, authErr.Code)
}

func (s *StatelessLoginSuite) TestLogin_WrongPassword() {
	svc, mockUserRepo, _, _, _ := s.setupService()
	user := testutil.TestUser()

	mockUserRepo.EXPECT().FindByEmail(gomock.Any(), user.Email).Return(user, nil)
	// Lockout: failed login records attempt and updates user
	mockUserRepo.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)

	req := &dto.LoginRequest{Email: user.Email, Password: "wrongpassword"}
	_, authErr := svc.Login(context.Background(), req)

	s.NotNil(authErr)
	s.Equal(types.ErrInvalidCredentials, authErr.Code)
}

func (s *StatelessLoginSuite) TestLogin_AccountLocked() {
	// Need a service with lockout enabled in config
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenRepo := mocks.NewMockTokenRepository(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)

	secMgr := testutil.TestSecurityManager()
	cfg := &config.StatelessModuleConfig{RefreshTokenRotation: true}

	testCfg := testutil.TestConfig()
	testCfg.Security.Lockout = types.LockoutConfig{
		Enabled:         true,
		MaxAttempts:     5,
		LockoutDuration: 15 * time.Minute,
	}

	deps := config.ModuleDependencies{
		Config:           testCfg,
		Events:           mockEvents,
		Logger:           mockLogger,
		SecurityManager:  secMgr,
		AuthInterceptors: interceptor.NewRegistry(),
	}

	svc := services.NewStatelessService(deps, mockUserRepo, mockTokenRepo, mockLogger, secMgr, cfg)

	user := testutil.TestUser()
	future := time.Now().Add(10 * time.Minute)
	user.LockedUntil = &future
	user.FailedLoginAttempts = 5

	mockUserRepo.EXPECT().FindByEmail(gomock.Any(), user.Email).Return(user, nil)

	req := &dto.LoginRequest{Email: user.Email, Password: "password123"}
	_, authErr := svc.Login(context.Background(), req)

	s.NotNil(authErr)
	s.Equal(types.ErrAccountLocked, authErr.Code)
}

func (s *StatelessLoginSuite) TestLogin_JTISaveFails() {
	svc, mockUserRepo, mockTokenRepo, _, _ := s.setupService()
	user := testutil.TestUser()

	mockUserRepo.EXPECT().FindByEmail(gomock.Any(), user.Email).Return(user, nil)
	mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(errors.New("db error"))

	req := &dto.LoginRequest{Email: user.Email, Password: "password123"}
	_, authErr := svc.Login(context.Background(), req)

	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

func (s *StatelessLoginSuite) TestLogin_UpdateLastLoginFails_StillSucceeds() {
	svc, mockUserRepo, mockTokenRepo, mockLogger, _ := s.setupService()
	user := testutil.TestUser()

	mockUserRepo.EXPECT().FindByEmail(gomock.Any(), user.Email).Return(user, nil)
	mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(nil)
	mockUserRepo.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(errors.New("update failed"))
	mockLogger.EXPECT().Errorf(gomock.Any(), gomock.Any())

	req := &dto.LoginRequest{Email: user.Email, Password: "password123"}
	resp, authErr := svc.Login(context.Background(), req)

	s.Nil(authErr)
	s.NotNil(resp.AccessToken)
}

// --- Logout Tests ---

func (s *StatelessLoginSuite) TestLogout_Success() {
	svc, _, mockTokenRepo, _, _ := s.setupService()
	userID := "user-123"

	mockTokenRepo.EXPECT().DeleteByUserID(gomock.Any(), userID).Return(nil)

	authErr := svc.Logout(context.Background(), userID)
	s.Nil(authErr)
}

func (s *StatelessLoginSuite) TestLogout_DeleteFails() {
	svc, _, mockTokenRepo, _, _ := s.setupService()
	userID := "user-123"

	mockTokenRepo.EXPECT().DeleteByUserID(gomock.Any(), userID).Return(errors.New("db error"))

	authErr := svc.Logout(context.Background(), userID)
	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

// --- Refresh Tests ---

func (s *StatelessLoginSuite) TestRefresh_Success() {
	svc, mockUserRepo, mockTokenRepo, _, _ := s.setupService()
	user := testutil.TestUser()

	// Generate a real refresh token to parse
	refreshToken, jti, err := testutil.TestSecurityManager().GenerateStatelessRefreshToken(user)
	s.NoError(err)

	tokenRecord := &models.Token{
		ID:     "tok-1",
		UserID: user.ID,
		Type:   "refresh_nonce",
		Token:  jti,
	}

	mockTokenRepo.EXPECT().FindByToken(gomock.Any(), jti).Return(tokenRecord, nil)
	mockUserRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	mockTokenRepo.EXPECT().Delete(gomock.Any(), jti).Return(nil)
	mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(nil)

	req := &dto.RefreshRequest{RefreshToken: refreshToken}
	resp, authErr := svc.Refresh(context.Background(), req)

	s.Nil(authErr)
	s.NotNil(resp.AccessToken)
	s.NotNil(resp.RefreshToken)
}

func (s *StatelessLoginSuite) TestRefresh_InvalidJWT() {
	svc, _, _, _, _ := s.setupService()

	req := &dto.RefreshRequest{RefreshToken: "invalid.jwt.token"}
	_, authErr := svc.Refresh(context.Background(), req)

	s.NotNil(authErr)
	s.Equal(types.ErrInvalidCredentials, authErr.Code)
}

func (s *StatelessLoginSuite) TestRefresh_JTINotFound() {
	svc, _, mockTokenRepo, _, _ := s.setupService()
	user := testutil.TestUser()

	refreshToken, jti, err := testutil.TestSecurityManager().GenerateStatelessRefreshToken(user)
	s.NoError(err)
	_ = refreshToken

	mockTokenRepo.EXPECT().FindByToken(gomock.Any(), jti).Return(nil, models.ErrNotFound)

	req := &dto.RefreshRequest{RefreshToken: refreshToken}
	_, authErr := svc.Refresh(context.Background(), req)

	s.NotNil(authErr)
	s.Equal(types.ErrInvalidCredentials, authErr.Code)
}

func (s *StatelessLoginSuite) TestRefresh_UserNotFound() {
	svc, mockUserRepo, mockTokenRepo, _, _ := s.setupService()
	user := testutil.TestUser()

	refreshToken, jti, err := testutil.TestSecurityManager().GenerateStatelessRefreshToken(user)
	s.NoError(err)

	tokenRecord := &models.Token{Token: jti, UserID: user.ID}
	mockTokenRepo.EXPECT().FindByToken(gomock.Any(), jti).Return(tokenRecord, nil)
	mockUserRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(nil, models.ErrNotFound)

	req := &dto.RefreshRequest{RefreshToken: refreshToken}
	_, authErr := svc.Refresh(context.Background(), req)

	s.NotNil(authErr)
	s.Equal(types.ErrInvalidCredentials, authErr.Code)
}

func (s *StatelessLoginSuite) TestRefresh_DeleteOldNonceFails() {
	svc, mockUserRepo, mockTokenRepo, _, _ := s.setupService()
	user := testutil.TestUser()

	refreshToken, jti, err := testutil.TestSecurityManager().GenerateStatelessRefreshToken(user)
	s.NoError(err)

	tokenRecord := &models.Token{Token: jti, UserID: user.ID}
	mockTokenRepo.EXPECT().FindByToken(gomock.Any(), jti).Return(tokenRecord, nil)
	mockUserRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	mockTokenRepo.EXPECT().Delete(gomock.Any(), jti).Return(errors.New("db error"))

	req := &dto.RefreshRequest{RefreshToken: refreshToken}
	_, authErr := svc.Refresh(context.Background(), req)

	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

func (s *StatelessLoginSuite) TestRefresh_SaveNewNonceFails() {
	svc, mockUserRepo, mockTokenRepo, _, _ := s.setupService()
	user := testutil.TestUser()

	refreshToken, jti, err := testutil.TestSecurityManager().GenerateStatelessRefreshToken(user)
	s.NoError(err)

	tokenRecord := &models.Token{Token: jti, UserID: user.ID}
	mockTokenRepo.EXPECT().FindByToken(gomock.Any(), jti).Return(tokenRecord, nil)
	mockUserRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	mockTokenRepo.EXPECT().Delete(gomock.Any(), jti).Return(nil)
	mockTokenRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(errors.New("db error"))

	req := &dto.RefreshRequest{RefreshToken: refreshToken}
	_, authErr := svc.Refresh(context.Background(), req)

	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}
