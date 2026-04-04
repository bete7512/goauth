package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/oauth/providers"
	"github.com/bete7512/goauth/internal/modules/oauth/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type OAuthServiceSuite struct {
	suite.Suite
}

func TestOAuthServiceSuite(t *testing.T) {
	suite.Run(t, new(OAuthServiceSuite))
}

type oauthTestSetup struct {
	svc         services.OAuthService
	userRepo    *mocks.MockUserRepository
	tokenRepo   *mocks.MockTokenRepository
	accountRepo *mocks.MockAccountRepository
	sessionRepo *mocks.MockSessionRepository
	provider    *mocks.MockOAuthProvider
	events      *mocks.MockEventBus
	logger      *mocks.MockLogger
	registry    *providers.Registry
}

func (s *OAuthServiceSuite) setup(cfgOverrides ...func(*config.OAuthModuleConfig)) *oauthTestSetup {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenRepo := mocks.NewMockTokenRepository(ctrl)
	mockAccountRepo := mocks.NewMockAccountRepository(ctrl)
	mockSessionRepo := mocks.NewMockSessionRepository(ctrl)
	mockProvider := mocks.NewMockOAuthProvider(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	// Allow any logger calls — use gomock.Any() for variadic args
	mockLogger.EXPECT().Errorf(gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Errorf(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Warnf(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Infof(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Infof(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Infof(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Trace(gomock.Any(), gomock.Any()).AnyTimes()
	mockLogger.EXPECT().Trace(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	// Register provider in registry
	registry := providers.NewRegistry()
	mockProvider.EXPECT().Name().Return("google").AnyTimes()
	registry.Register(mockProvider)

	cfg := &config.OAuthModuleConfig{
		AllowSignup:            true,
		AllowAccountLinking:    true,
		TrustEmailVerification: true,
		StateTTL:               10 * time.Minute,
		UseSessionAuth:         false,
	}
	for _, override := range cfgOverrides {
		override(cfg)
	}

	secMgr := testutil.TestSecurityManager()

	deps := config.ModuleDependencies{
		Config:           testutil.TestConfig(),
		Events:           mockEvents,
		Logger:           mockLogger,
		SecurityManager:  secMgr,
		AuthInterceptors: interceptor.NewRegistry(),
	}

	svc := services.NewOAuthService(
		deps, cfg, registry,
		mockUserRepo, mockTokenRepo, mockAccountRepo, mockSessionRepo,
		secMgr,
		"http://localhost:8080", "/auth",
	)

	return &oauthTestSetup{
		svc:         svc,
		userRepo:    mockUserRepo,
		tokenRepo:   mockTokenRepo,
		accountRepo: mockAccountRepo,
		sessionRepo: mockSessionRepo,
		provider:    mockProvider,
		events:      mockEvents,
		logger:      mockLogger,
		registry:    registry,
	}
}

// --- InitiateLogin Tests ---

func (s *OAuthServiceSuite) TestInitiateLogin_Success() {
	t := s.setup()
	t.provider.EXPECT().AuthCodeURL(gomock.Any(), gomock.Any()).Return("https://accounts.google.com/authorize?state=abc")
	t.tokenRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Token{})).Return(nil)

	authURL, authErr := t.svc.InitiateLogin(context.Background(), "google", "http://frontend.com/callback")

	s.Nil(authErr)
	s.Contains(authURL, "accounts.google.com")
}

func (s *OAuthServiceSuite) TestInitiateLogin_UnknownProvider() {
	t := s.setup()

	_, authErr := t.svc.InitiateLogin(context.Background(), "facebook", "")

	s.NotNil(authErr)
	s.Equal(types.ErrOAuthProviderNotFound, authErr.Code)
}

func (s *OAuthServiceSuite) TestInitiateLogin_StateSaveFails() {
	t := s.setup()
	t.tokenRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("db error"))

	_, authErr := t.svc.InitiateLogin(context.Background(), "google", "")

	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

// --- HandleCallback Tests ---

func (s *OAuthServiceSuite) validStateToken() *models.Token {
	return &models.Token{
		ID:        "state-1",
		Type:      models.TokenTypeOAuthState,
		Token:     "valid-state",
		Code:      "code-verifier-123",
		Email:     "http://frontend.com/callback",
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
	}
}

func (s *OAuthServiceSuite) validTokenResponse() *providers.TokenResponse {
	return &providers.TokenResponse{
		AccessToken:  "provider-access-token",
		RefreshToken: "provider-refresh-token",
		ExpiresIn:    3600,
	}
}

func (s *OAuthServiceSuite) validUserInfo() *providers.UserInfo {
	return &providers.UserInfo{
		ID:            "google-user-123",
		Email:         "alice@example.com",
		EmailVerified: true,
		Name:          "Alice Smith",
		FirstName:     "Alice",
		LastName:      "Smith",
	}
}

func (s *OAuthServiceSuite) TestHandleCallback_NewUser() {
	t := s.setup()
	state := s.validStateToken()
	tokenResp := s.validTokenResponse()
	userInfo := s.validUserInfo()
	metadata := &types.RequestMetadata{IPAddress: "127.0.0.1", UserAgent: "TestAgent"}

	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "valid-state").Return(state, nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), state.ID).Return(nil)
	t.provider.EXPECT().SupportsOIDC().Return(false)
	t.provider.EXPECT().Exchange(gomock.Any(), "auth-code", gomock.Any()).Return(tokenResp, nil)
	t.provider.EXPECT().UserInfo(gomock.Any(), tokenResp.AccessToken).Return(userInfo, nil)
	// findOrCreateUser: no existing account, no email match, create new
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), "google", userInfo.ID).Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), userInfo.Email).Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
	t.accountRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Account{})).Return(nil)
	t.userRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil) // last login update
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterSignup, gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOAuthLinkAdded, gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterOAuthLogin, gomock.Any()).Return(nil)

	result, authErr := t.svc.HandleCallback(context.Background(), "google", "auth-code", "valid-state", metadata)

	s.Nil(authErr)
	s.NotNil(result)
	s.True(result.IsNewUser)
	s.NotEmpty(result.AccessToken)
	s.NotEmpty(result.RefreshToken)
	s.Equal("google", result.Provider)
}

func (s *OAuthServiceSuite) TestHandleCallback_ExistingLinkedUser() {
	t := s.setup()
	state := s.validStateToken()
	tokenResp := s.validTokenResponse()
	userInfo := s.validUserInfo()
	user := testutil.TestUser()
	metadata := &types.RequestMetadata{IPAddress: "127.0.0.1"}

	existingAccount := &models.Account{
		ID:                "acc-1",
		UserID:            user.ID,
		Provider:          "google",
		ProviderAccountID: userInfo.ID,
	}

	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "valid-state").Return(state, nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), state.ID).Return(nil)
	t.provider.EXPECT().SupportsOIDC().Return(false)
	t.provider.EXPECT().Exchange(gomock.Any(), "auth-code", gomock.Any()).Return(tokenResp, nil)
	t.provider.EXPECT().UserInfo(gomock.Any(), tokenResp.AccessToken).Return(userInfo, nil)
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), "google", userInfo.ID).Return(existingAccount, nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	t.userRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil) // last login
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterOAuthLogin, gomock.Any()).Return(nil)

	result, authErr := t.svc.HandleCallback(context.Background(), "google", "auth-code", "valid-state", metadata)

	s.Nil(authErr)
	s.False(result.IsNewUser)
	s.Equal(user.ID, result.User.ID)
}

func (s *OAuthServiceSuite) TestHandleCallback_EmailMatchLinking() {
	t := s.setup()
	state := s.validStateToken()
	tokenResp := s.validTokenResponse()
	userInfo := s.validUserInfo()
	user := testutil.TestUser()
	user.Email = userInfo.Email
	metadata := &types.RequestMetadata{IPAddress: "127.0.0.1"}

	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "valid-state").Return(state, nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), state.ID).Return(nil)
	t.provider.EXPECT().SupportsOIDC().Return(false)
	t.provider.EXPECT().Exchange(gomock.Any(), "auth-code", gomock.Any()).Return(tokenResp, nil)
	t.provider.EXPECT().UserInfo(gomock.Any(), tokenResp.AccessToken).Return(userInfo, nil)
	// No existing account
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), "google", userInfo.ID).Return(nil, models.ErrNotFound)
	// But email matches existing user
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), userInfo.Email).Return(user, nil)
	t.accountRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.Account{})).Return(nil) // link
	t.userRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)                                    // last login
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOAuthLinkAdded, gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterOAuthLogin, gomock.Any()).Return(nil)

	result, authErr := t.svc.HandleCallback(context.Background(), "google", "auth-code", "valid-state", metadata)

	s.Nil(authErr)
	s.False(result.IsNewUser)
}

func (s *OAuthServiceSuite) TestHandleCallback_InvalidState() {
	t := s.setup()
	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "invalid-state").Return(nil, models.ErrNotFound)

	_, authErr := t.svc.HandleCallback(context.Background(), "google", "code", "invalid-state", nil)

	s.NotNil(authErr)
	s.Equal(types.ErrOAuthInvalidState, authErr.Code)
}

func (s *OAuthServiceSuite) TestHandleCallback_ExpiredState() {
	t := s.setup()
	state := s.validStateToken()
	state.ExpiresAt = time.Now().Add(-1 * time.Hour)

	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "valid-state").Return(state, nil)

	_, authErr := t.svc.HandleCallback(context.Background(), "google", "code", "valid-state", nil)

	s.NotNil(authErr)
	s.Equal(types.ErrOAuthStateExpired, authErr.Code)
}

func (s *OAuthServiceSuite) TestHandleCallback_UsedState() {
	t := s.setup()
	state := s.validStateToken()
	state.Used = true

	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "valid-state").Return(state, nil)

	_, authErr := t.svc.HandleCallback(context.Background(), "google", "code", "valid-state", nil)

	s.NotNil(authErr)
	s.Equal(types.ErrOAuthStateUsed, authErr.Code)
}

func (s *OAuthServiceSuite) TestHandleCallback_CodeExchangeFails() {
	t := s.setup()
	state := s.validStateToken()

	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "valid-state").Return(state, nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), state.ID).Return(nil)
	t.provider.EXPECT().Exchange(gomock.Any(), "bad-code", gomock.Any()).Return(nil, errors.New("invalid code"))

	_, authErr := t.svc.HandleCallback(context.Background(), "google", "bad-code", "valid-state", nil)

	s.NotNil(authErr)
	s.Equal(types.ErrOAuthTokenExchange, authErr.Code)
}

func (s *OAuthServiceSuite) TestHandleCallback_UserInfoFails() {
	t := s.setup()
	state := s.validStateToken()
	tokenResp := s.validTokenResponse()

	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "valid-state").Return(state, nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), state.ID).Return(nil)
	t.provider.EXPECT().SupportsOIDC().Return(false)
	t.provider.EXPECT().Exchange(gomock.Any(), "auth-code", gomock.Any()).Return(tokenResp, nil)
	t.provider.EXPECT().UserInfo(gomock.Any(), tokenResp.AccessToken).Return(nil, errors.New("provider error"))

	_, authErr := t.svc.HandleCallback(context.Background(), "google", "auth-code", "valid-state", nil)

	s.NotNil(authErr)
	s.Equal(types.ErrOAuthUserInfo, authErr.Code)
}

func (s *OAuthServiceSuite) TestHandleCallback_SignupDisabled() {
	t := s.setup(func(c *config.OAuthModuleConfig) {
		c.AllowSignup = false
	})
	state := s.validStateToken()
	tokenResp := s.validTokenResponse()
	userInfo := s.validUserInfo()

	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "valid-state").Return(state, nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), state.ID).Return(nil)
	t.provider.EXPECT().SupportsOIDC().Return(false)
	t.provider.EXPECT().Exchange(gomock.Any(), "auth-code", gomock.Any()).Return(tokenResp, nil)
	t.provider.EXPECT().UserInfo(gomock.Any(), tokenResp.AccessToken).Return(userInfo, nil)
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), "google", userInfo.ID).Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), userInfo.Email).Return(nil, models.ErrNotFound)

	_, authErr := t.svc.HandleCallback(context.Background(), "google", "auth-code", "valid-state", nil)

	s.NotNil(authErr)
	s.Equal(types.ErrOAuthSignupDisabled, authErr.Code)
}

func (s *OAuthServiceSuite) TestHandleCallback_AccountLinkingDisabled() {
	t := s.setup(func(c *config.OAuthModuleConfig) {
		c.AllowAccountLinking = false
	})
	state := s.validStateToken()
	tokenResp := s.validTokenResponse()
	userInfo := s.validUserInfo()
	existingUser := testutil.TestUser()
	existingUser.Email = userInfo.Email

	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), "valid-state").Return(state, nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), state.ID).Return(nil)
	t.provider.EXPECT().SupportsOIDC().Return(false)
	t.provider.EXPECT().Exchange(gomock.Any(), "auth-code", gomock.Any()).Return(tokenResp, nil)
	t.provider.EXPECT().UserInfo(gomock.Any(), tokenResp.AccessToken).Return(userInfo, nil)
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), "google", userInfo.ID).Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), userInfo.Email).Return(existingUser, nil)

	_, authErr := t.svc.HandleCallback(context.Background(), "google", "auth-code", "valid-state", nil)

	s.NotNil(authErr)
	s.Equal(types.ErrOAuthAccountLinkingDisabled, authErr.Code)
}

// --- UnlinkProvider Tests ---

func (s *OAuthServiceSuite) TestUnlinkProvider_Success() {
	t := s.setup()
	user := testutil.TestUser()
	account := &models.Account{ID: "acc-1", UserID: user.ID, Provider: "google", ProviderAccountID: "g-123"}

	t.accountRepo.EXPECT().FindByUserIDAndProvider(gomock.Any(), user.ID, "google").Return(account, nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil) // user has password
	t.accountRepo.EXPECT().Delete(gomock.Any(), account.ID).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOAuthLinkRemoved, gomock.Any()).Return(nil)

	authErr := t.svc.UnlinkProvider(context.Background(), user.ID, "google")
	s.Nil(authErr)
}

func (s *OAuthServiceSuite) TestUnlinkProvider_NotLinked() {
	t := s.setup()

	t.accountRepo.EXPECT().FindByUserIDAndProvider(gomock.Any(), "user-1", "google").Return(nil, models.ErrNotFound)

	authErr := t.svc.UnlinkProvider(context.Background(), "user-1", "google")
	s.NotNil(authErr)
	s.Equal(types.ErrOAuthNotLinked, authErr.Code)
}

func (s *OAuthServiceSuite) TestUnlinkProvider_OnlyLoginMethod() {
	t := s.setup()
	user := testutil.TestUser()
	user.PasswordHash = "" // no password
	account := &models.Account{ID: "acc-1", UserID: user.ID, Provider: "google"}

	t.accountRepo.EXPECT().FindByUserIDAndProvider(gomock.Any(), user.ID, "google").Return(account, nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	t.accountRepo.EXPECT().CountByUserID(gomock.Any(), user.ID).Return(int64(1), nil)

	authErr := t.svc.UnlinkProvider(context.Background(), user.ID, "google")
	s.NotNil(authErr)
	s.Contains(authErr.Message, "only login method")
}

func (s *OAuthServiceSuite) TestUnlinkProvider_HasOtherProvider() {
	t := s.setup()
	user := testutil.TestUser()
	user.PasswordHash = ""
	account := &models.Account{ID: "acc-1", UserID: user.ID, Provider: "google", ProviderAccountID: "g-123"}

	t.accountRepo.EXPECT().FindByUserIDAndProvider(gomock.Any(), user.ID, "google").Return(account, nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	t.accountRepo.EXPECT().CountByUserID(gomock.Any(), user.ID).Return(int64(2), nil) // has another
	t.accountRepo.EXPECT().Delete(gomock.Any(), account.ID).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventOAuthLinkRemoved, gomock.Any()).Return(nil)

	authErr := t.svc.UnlinkProvider(context.Background(), user.ID, "google")
	s.Nil(authErr)
}

// --- GetLinkedProviders Tests ---

func (s *OAuthServiceSuite) TestGetLinkedProviders_Success() {
	t := s.setup()
	accounts := []*models.Account{
		{Provider: "google"},
		{Provider: "github"},
	}
	t.accountRepo.EXPECT().FindByUserID(gomock.Any(), "user-1").Return(accounts, nil)

	linked, authErr := t.svc.GetLinkedProviders(context.Background(), "user-1")
	s.Nil(authErr)
	s.Equal([]string{"google", "github"}, linked)
}

func (s *OAuthServiceSuite) TestGetLinkedProviders_Empty() {
	t := s.setup()
	t.accountRepo.EXPECT().FindByUserID(gomock.Any(), "user-1").Return(nil, nil)

	linked, authErr := t.svc.GetLinkedProviders(context.Background(), "user-1")
	s.Nil(authErr)
	s.Empty(linked)
}

func (s *OAuthServiceSuite) TestGetLinkedProviders_RepoError() {
	t := s.setup()
	t.accountRepo.EXPECT().FindByUserID(gomock.Any(), "user-1").Return(nil, errors.New("db error"))

	_, authErr := t.svc.GetLinkedProviders(context.Background(), "user-1")
	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

// --- ListEnabledProviders ---

func (s *OAuthServiceSuite) TestListEnabledProviders() {
	t := s.setup()
	providers := t.svc.ListEnabledProviders()
	s.Contains(providers, "google")
}
