package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/saml/providers"
	"github.com/bete7512/goauth/internal/modules/saml/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type SAMLServiceSuite struct {
	suite.Suite
}

func TestSAMLServiceSuite(t *testing.T) {
	suite.Run(t, new(SAMLServiceSuite))
}

type noopLogger struct{}

func (noopLogger) Info(string, ...interface{})                      {}
func (noopLogger) Error(string, ...interface{})                     {}
func (noopLogger) Debug(string, ...interface{})                     {}
func (noopLogger) Warn(string, ...interface{})                      {}
func (noopLogger) Trace(string, ...interface{})                     {}
func (noopLogger) Infof(string, ...interface{})                     {}
func (noopLogger) Tracef(string, ...interface{})                    {}
func (noopLogger) Errorf(string, ...interface{})                    {}
func (noopLogger) Debugf(string, ...interface{})                    {}
func (noopLogger) Warnf(string, ...interface{})                     {}
func (noopLogger) Fatalf(string, ...interface{})                    {}
func (l noopLogger) WithFields(map[string]interface{}) types.Logger { return l }

type samlTestSetup struct {
	svc         services.SAMLService
	userRepo    *mocks.MockUserRepository
	tokenRepo   *mocks.MockTokenRepository
	accountRepo *mocks.MockAccountRepository
	provider    *mocks.MockServiceProvider
	events      *mocks.MockEventBus
}

const (
	connection = "keycloak"
	issuer     = "https://idp.example.com/realms/test"
	requestID  = "id-0123456789abcdef"
)

func (s *SAMLServiceSuite) setup(overrides ...func(*config.SAMLModuleConfig)) *samlTestSetup {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	accountRepo := mocks.NewMockAccountRepository(ctrl)
	provider := mocks.NewMockServiceProvider(ctrl)
	events := mocks.NewMockEventBus(ctrl)

	provider.EXPECT().Name().Return(connection).AnyTimes()
	provider.EXPECT().IssuerEntityID().Return(issuer).AnyTimes()
	registry := providers.NewRegistry()
	s.Require().NoError(registry.Register(provider))

	cfg := &config.SAMLModuleConfig{AllowSignup: true, TrustEmail: true, RequestTTL: 10 * time.Minute}
	for _, override := range overrides {
		override(cfg)
	}
	secMgr := testutil.TestSecurityManager()
	deps := config.ModuleDependencies{
		Config:           testutil.TestConfig(),
		Events:           events,
		Logger:           noopLogger{},
		SecurityManager:  secMgr,
		AuthInterceptors: interceptor.NewRegistry(),
	}
	svc := services.NewSAMLService(deps, cfg, registry, userRepo, tokenRepo, accountRepo, nil, secMgr)
	return &samlTestSetup{svc: svc, userRepo: userRepo, tokenRepo: tokenRepo, accountRepo: accountRepo, provider: provider, events: events}
}

func pendingRequest(redirect string) *models.Token {
	data, _ := json.Marshal(map[string]string{"connection": connection, "redirect": redirect})
	return &models.Token{ID: "tok-1", Type: models.TokenTypeSAMLRequest, Token: requestID, Data: string(data), ExpiresAt: time.Now().Add(5 * time.Minute)}
}

func identity() *providers.Identity {
	return &providers.Identity{
		NameID:       "subject-1",
		NameIDFormat: providers.PersistentNameIDFormat,
		Issuer:       issuer,
		Email:        "alice@example.com",
		FirstName:    "Alice",
		LastName:     "Liddell",
		Name:         "Alice Liddell",
		Attributes:   map[string][]string{"email": {"alice@example.com"}},
	}
}

func acsRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "https://sp.example.com/auth/saml/keycloak/acs", nil)
}

func metadata() *types.RequestMetadata {
	return &types.RequestMetadata{IPAddress: "127.0.0.1", UserAgent: "test", Timestamp: time.Now()}
}

// --- InitiateLogin ---

func (s *SAMLServiceSuite) TestInitiateLogin_StoresRequestID() {
	t := s.setup()
	t.provider.EXPECT().AuthnRequest(gomock.Any()).Return("https://idp.example.com/sso?SAMLRequest=x&RelayState="+requestID, requestID, nil)
	t.tokenRepo.EXPECT().Create(gomock.Any(), gomock.Cond(func(tok *models.Token) bool {
		var c map[string]string
		_ = json.Unmarshal([]byte(tok.Data), &c)
		return tok.Type == models.TokenTypeSAMLRequest && tok.Token == requestID && c["connection"] == connection && c["redirect"] == "https://app.example.com/done"
	})).Return(nil)

	start, authErr := t.svc.InitiateLogin(context.Background(), connection, "https://app.example.com/done")
	s.Nil(authErr)
	s.Equal(requestID, start.RequestID)
	s.Contains(start.RedirectURL, "idp.example.com/sso")
}

func (s *SAMLServiceSuite) TestInitiateLogin_UnknownProvider() {
	t := s.setup()
	_, authErr := t.svc.InitiateLogin(context.Background(), "nope", "")
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLProviderNotFound, authErr.Code)
}

func (s *SAMLServiceSuite) TestInitiateLogin_ProviderFailure() {
	t := s.setup()
	t.provider.EXPECT().AuthnRequest(gomock.Any()).Return("", "", errors.New("no sso endpoint"))
	_, authErr := t.svc.InitiateLogin(context.Background(), connection, "")
	s.NotNil(authErr)
	s.Equal(types.ErrInternalError, authErr.Code)
}

// --- HandleACS: request binding ---

func (s *SAMLServiceSuite) TestHandleACS_UnknownRequest() {
	t := s.setup()
	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), requestID).Return(nil, models.ErrNotFound)
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLInvalidRequest, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_ExpiredRequest() {
	t := s.setup()
	pending := pendingRequest("")
	pending.ExpiresAt = time.Now().Add(-time.Minute)
	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), requestID).Return(pending, nil)
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLRequestExpired, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_RequestForOtherConnection() {
	t := s.setup()
	pending := pendingRequest("")
	data, _ := json.Marshal(map[string]string{"connection": "okta"})
	pending.Data = string(data)
	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), requestID).Return(pending, nil)
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLInvalidRequest, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_ReplayLosesConsumeRace() {
	t := s.setup()
	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), requestID).Return(pendingRequest(""), nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), "tok-1").Return(errors.New("conflict"))
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLInvalidRequest, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_IDPInitiatedDisabled() {
	t := s.setup()
	t.provider.EXPECT().AllowIDPInitiated().Return(false)
	_, authErr := t.svc.HandleACS(context.Background(), connection, "", acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLIDPInitiatedDisabled, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_InvalidResponseHidesCause() {
	t := s.setup()
	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), requestID).Return(pendingRequest(""), nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), "tok-1").Return(nil)
	t.provider.EXPECT().ParseResponse(gomock.Any(), []string{requestID}).Return(nil, errors.New("cannot validate signature on Response"))
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLInvalidResponse, authErr.Code)
	s.NotContains(authErr.Message, "signature")
}

func (s *SAMLServiceSuite) TestHandleACS_IssuerMismatch() {
	t := s.setup()
	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), requestID).Return(pendingRequest(""), nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), "tok-1").Return(nil)
	id := identity()
	id.Issuer = "https://other-idp.example.com"
	t.provider.EXPECT().ParseResponse(gomock.Any(), []string{requestID}).Return(id, nil)
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLInvalidResponse, authErr.Code)
}

// --- HandleACS: identity resolution ---

func (s *SAMLServiceSuite) expectVerifiedResponse(t *samlTestSetup, id *providers.Identity, redirect string) {
	t.tokenRepo.EXPECT().FindByToken(gomock.Any(), requestID).Return(pendingRequest(redirect), nil)
	t.tokenRepo.EXPECT().MarkAsUsed(gomock.Any(), "tok-1").Return(nil)
	t.provider.EXPECT().ParseResponse(gomock.Any(), []string{requestID}).Return(id, nil)
}

func (s *SAMLServiceSuite) expectCompletion(t *samlTestSetup) {
	t.userRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
	t.tokenRepo.EXPECT().Create(gomock.Any(), gomock.Cond(func(token *models.Token) bool { return token.Type == "refresh_nonce" })).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterSAMLLogin, gomock.Any()).Return(nil)
}

func (s *SAMLServiceSuite) TestHandleACS_NewUser() {
	t := s.setup()
	id := identity()
	s.expectVerifiedResponse(t, id, "https://app.example.com/done")
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "alice@example.com").Return(nil, models.ErrNotFound)
	var created *models.User
	t.userRepo.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).DoAndReturn(func(_ context.Context, u *models.User) error {
		created = u
		return nil
	})
	t.accountRepo.EXPECT().Create(gomock.Any(), gomock.Cond(func(a *models.Account) bool {
		return a.Provider == connection && a.ProviderAccountID == "subject-1" && a.Type == string(models.AccountTypeSAML) && a.Issuer == issuer
	})).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventSAMLLinkAdded, gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterSignup, gomock.Any()).Return(nil)
	s.expectCompletion(t)

	result, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.Nil(authErr)
	s.True(result.IsNewUser)
	s.Equal("https://app.example.com/done", result.ClientRedirectURI)
	s.Equal("subject-1", result.NameID)
	s.NotEmpty(result.AccessToken)
	s.NotEmpty(result.RefreshToken)
	s.Equal("alice@example.com", created.Email)
	s.True(created.EmailVerified, "an IdP-released email is trusted")
	s.Equal("Alice", created.FirstName)
	s.Empty(created.PasswordHash)
}

func (s *SAMLServiceSuite) TestHandleACS_NewUserEmailNotTrusted() {
	t := s.setup(func(c *config.SAMLModuleConfig) { c.TrustEmail = false })
	s.expectVerifiedResponse(t, identity(), "")
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "alice@example.com").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().Create(gomock.Any(), gomock.Cond(func(u *models.User) bool { return !u.EmailVerified })).Return(nil)
	t.accountRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventSAMLLinkAdded, gomock.Any()).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventAfterSignup, gomock.Any()).Return(nil)
	s.expectCompletion(t)

	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.Nil(authErr)
}

func (s *SAMLServiceSuite) TestHandleACS_ExistingLinkedSubject() {
	t := s.setup()
	s.expectVerifiedResponse(t, identity(), "")
	user := testutil.TestUser()
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(&models.Account{UserID: user.ID, Type: string(models.AccountTypeSAML), Issuer: issuer, RealmID: "default"}, nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	s.expectCompletion(t)

	result, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.Nil(authErr)
	s.False(result.IsNewUser)
	s.Equal(user.ID, result.User.ID)
}

func (s *SAMLServiceSuite) TestHandleACS_LinkedSubjectFromOtherIssuerRejected() {
	t := s.setup()
	s.expectVerifiedResponse(t, identity(), "")
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(&models.Account{UserID: "u", Type: string(models.AccountTypeSAML), Issuer: "https://old-idp"}, nil)
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLAccountLinkingDisabled, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_EmailMatchLinkingDisabled() {
	t := s.setup()
	s.expectVerifiedResponse(t, identity(), "")
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "alice@example.com").Return(testutil.TestUser(), nil)
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLAccountLinkingDisabled, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_EmailMatchLinksWhenAllowed() {
	t := s.setup(func(c *config.SAMLModuleConfig) { c.AllowAccountLinking = true })
	s.expectVerifiedResponse(t, identity(), "")
	user := testutil.TestUser()
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "alice@example.com").Return(user, nil)
	t.accountRepo.EXPECT().Create(gomock.Any(), gomock.Cond(func(a *models.Account) bool { return a.UserID == user.ID })).Return(nil)
	t.events.EXPECT().EmitAsync(gomock.Any(), types.EventSAMLLinkAdded, gomock.Any()).Return(nil)
	s.expectCompletion(t)

	result, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.Nil(authErr)
	s.False(result.IsNewUser)
	s.Equal(user.ID, result.User.ID)
}

func (s *SAMLServiceSuite) TestHandleACS_SignupDisabled() {
	t := s.setup(func(c *config.SAMLModuleConfig) { c.AllowSignup = false })
	s.expectVerifiedResponse(t, identity(), "")
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(nil, models.ErrNotFound)
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "alice@example.com").Return(nil, models.ErrNotFound)
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLSignupDisabled, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_EmailRequiredForSignup() {
	t := s.setup()
	id := identity()
	id.Email = ""
	s.expectVerifiedResponse(t, id, "")
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(nil, models.ErrNotFound)
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLEmailRequired, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_TransientSubjectCannotSignUp() {
	t := s.setup()
	id := identity()
	id.NameIDFormat = providers.TransientNameIDFormat
	s.expectVerifiedResponse(t, id, "")
	// No account lookup for a transient subject; straight to email.
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "alice@example.com").Return(nil, models.ErrNotFound)
	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
	s.Equal(types.ErrSAMLSubjectNotPersistent, authErr.Code)
}

func (s *SAMLServiceSuite) TestHandleACS_TransientSubjectUsesEmailWithoutLinking() {
	t := s.setup(func(c *config.SAMLModuleConfig) { c.AllowAccountLinking = true })
	id := identity()
	id.NameIDFormat = providers.TransientNameIDFormat
	s.expectVerifiedResponse(t, id, "")
	user := testutil.TestUser()
	t.userRepo.EXPECT().FindByEmail(gomock.Any(), "alice@example.com").Return(user, nil)
	s.expectCompletion(t)

	result, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.Nil(authErr)
	s.Equal(user.ID, result.User.ID)
}

func (s *SAMLServiceSuite) TestHandleACS_IDPInitiatedAllowed() {
	t := s.setup()
	t.provider.EXPECT().AllowIDPInitiated().Return(true)
	t.provider.EXPECT().ParseResponse(gomock.Any(), gomock.Nil()).Return(identity(), nil)
	user := testutil.TestUser()
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(&models.Account{UserID: user.ID, Type: string(models.AccountTypeSAML), Issuer: issuer}, nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	s.expectCompletion(t)

	result, authErr := t.svc.HandleACS(context.Background(), connection, "", acsRequest(), metadata())
	s.Nil(authErr)
	s.Empty(result.ClientRedirectURI)
}

func (s *SAMLServiceSuite) TestHandleACS_InactiveUserDenied() {
	t := s.setup()
	s.expectVerifiedResponse(t, identity(), "")
	user := testutil.TestUser()
	user.Active = false
	t.accountRepo.EXPECT().FindByProviderAndAccountID(gomock.Any(), connection, "subject-1").Return(&models.Account{UserID: user.ID, Type: string(models.AccountTypeSAML), Issuer: issuer}, nil)
	t.userRepo.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	t.userRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)

	_, authErr := t.svc.HandleACS(context.Background(), connection, requestID, acsRequest(), metadata())
	s.NotNil(authErr)
}

// --- Metadata / ListProviders ---

func (s *SAMLServiceSuite) TestMetadataAndList() {
	t := s.setup()
	t.provider.EXPECT().Metadata().Return([]byte("<EntityDescriptor/>"), nil)
	out, authErr := t.svc.Metadata(connection)
	s.Nil(authErr)
	s.Equal("<EntityDescriptor/>", string(out))
	_, authErr = t.svc.Metadata("missing")
	s.NotNil(authErr)
	s.Equal([]string{connection}, t.svc.ListProviders())
}
