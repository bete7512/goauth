package services_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/idp/services"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type IDPServiceSuite struct {
	suite.Suite
}

func TestIDPServiceSuite(t *testing.T) {
	suite.Run(t, new(IDPServiceSuite))
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

const (
	clientID     = "dashboard"
	clientSecret = "0123456789abcdef0123456789abcdef"
	redirectURI  = "https://dashboard.example.com/callback"
)

type idpTestSetup struct {
	svc          services.IDPService
	settings     *services.Settings
	clients      *mocks.MockIDPClientRepository
	grants       *mocks.MockIDPGrantRepository
	users        *mocks.MockUserRepository
	tokens       *mocks.MockTokenRepository
	events       *mocks.MockEventBus
	interceptors types.AuthInterceptorRegistry
}

func (s *IDPServiceSuite) setup(overrides ...func(*services.Settings)) *idpTestSetup {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	signer, err := security.NewTokenSigner(types.SecurityConfig{
		JWTAlgorithm:     types.JWTAlgorithmRS256,
		JWTPrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	})
	s.Require().NoError(err)
	settings := &services.Settings{
		Issuer:     "https://api.example.com/auth/oidc",
		ConsentURL: "https://app.example.com/oidc/consent",
		Signer:     signer,
		IDTokenTTL: time.Hour, AccessTokenTTL: time.Hour, RefreshTokenTTL: 30 * 24 * time.Hour,
		RefreshReuseLeeway: 10 * time.Second, CodeTTL: time.Minute, RequestTTL: 10 * time.Minute,
	}
	for _, override := range overrides {
		override(settings)
	}

	setup := &idpTestSetup{
		settings:     settings,
		clients:      mocks.NewMockIDPClientRepository(ctrl),
		grants:       mocks.NewMockIDPGrantRepository(ctrl),
		users:        mocks.NewMockUserRepository(ctrl),
		tokens:       mocks.NewMockTokenRepository(ctrl),
		events:       mocks.NewMockEventBus(ctrl),
		interceptors: interceptor.NewRegistry(),
	}
	deps := config.ModuleDependencies{
		Config:           testutil.TestConfig(),
		Events:           setup.events,
		Logger:           noopLogger{},
		SecurityManager:  testutil.TestSecurityManager(),
		AuthInterceptors: setup.interceptors,
	}
	setup.svc = services.NewIDPService(deps, settings, services.Stores{
		Clients: setup.clients, Grants: setup.grants, Users: setup.users, Tokens: setup.tokens,
	})
	return setup
}

func confidentialClient() *models.IDPClient {
	return &models.IDPClient{
		ID: "client-row-1", ClientID: clientID, Name: "Dashboard", SecretHash: services.ClientSecretDigest(clientSecret),
		RedirectURIs: models.StringList{redirectURI}, Scopes: models.StringList{"openid", "profile", "email", "offline_access"},
		RequirePKCE: true,
	}
}

// storedToken builds the record behind an access or refresh token of user.
func storedToken(tokenType, raw string, user *models.User, scopes ...string) *models.Token {
	data, _ := json.Marshal(services.TokenData{
		GrantID: "grant-1", ClientID: clientID, UserID: user.ID, Scopes: scopes,
		AuthTime: time.Now().Add(-time.Minute).Unix(), AMR: []string{"password"}, Binding: services.CredentialBinding(user),
	})
	return &models.Token{
		ID: "token-row-1", Type: tokenType, Token: security.TokenDigest(raw), Data: string(data),
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now().Add(-time.Minute),
	}
}

func refreshForm(raw string) *services.TokenRequest {
	return &services.TokenRequest{
		Form:    url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}},
		BasicID: clientID, BasicSecret: clientSecret, HasBasic: true,
	}
}

// --- Seed ---

func (s *IDPServiceSuite) TestSeedCreatesAMissingClient() {
	t := s.setup(func(settings *services.Settings) {
		settings.SeedClients = []config.IDPClientConfig{{ClientID: clientID, Secret: clientSecret, Name: "Dashboard", RedirectURIs: []string{redirectURI}, SkipConsent: true}}
	})
	ctx := context.Background()
	var created *models.IDPClient
	t.clients.EXPECT().FindByClientID(ctx, clientID).Return(nil, models.ErrNotFound)
	t.clients.EXPECT().Create(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, client *models.IDPClient) error {
		created = client
		return nil
	})
	t.clients.EXPECT().List(ctx, gomock.Any()).Return(nil, int64(0), nil)

	s.Require().NoError(t.svc.Seed(ctx))
	s.Require().NotNil(created)
	s.True(created.Managed)
	s.Equal(clientID, created.ClientID)
	s.Equal(services.ClientSecretDigest(clientSecret), created.SecretHash)
	s.NotContains(created.SecretHash, clientSecret, "only a digest of the secret is stored")
	s.True(created.RequirePKCE, "PKCE is required unless configuration says otherwise")
	s.True(created.SkipConsent)
	s.Equal(models.StringList{"openid", "profile", "email"}, created.Scopes)
}

func (s *IDPServiceSuite) TestSeedRewritesAManagedClient() {
	t := s.setup(func(settings *services.Settings) {
		settings.SeedClients = []config.IDPClientConfig{{
			ClientID: clientID, Secret: "a-new-secret-0123456789abcdef0123456789", Name: "Dashboard v2",
			RedirectURIs: []string{"https://dashboard.example.com/v2"}, AllowWithoutPKCE: true,
		}}
	})
	ctx := context.Background()
	existing := confidentialClient()
	existing.Managed = true
	t.clients.EXPECT().FindByClientID(ctx, clientID).Return(existing, nil)
	t.clients.EXPECT().Update(ctx, existing).Return(nil)
	t.clients.EXPECT().List(ctx, gomock.Any()).Return([]*models.IDPClient{existing}, int64(1), nil)

	s.Require().NoError(t.svc.Seed(ctx))
	s.Equal("Dashboard v2", existing.Name)
	s.Equal(models.StringList{"https://dashboard.example.com/v2"}, existing.RedirectURIs)
	s.Equal(services.ClientSecretDigest("a-new-secret-0123456789abcdef0123456789"), existing.SecretHash)
	s.False(existing.RequirePKCE)
	s.True(existing.Managed)
	s.Equal("client-row-1", existing.ID, "the row keeps its identity")
}

// Configuration never takes over a client an administrator registered:
// that would silently replace its secret and redirect URIs.
func (s *IDPServiceSuite) TestSeedRefusesToTakeOverAnAPIClient() {
	t := s.setup(func(settings *services.Settings) {
		settings.SeedClients = []config.IDPClientConfig{{ClientID: clientID, Secret: clientSecret, Name: "Dashboard", RedirectURIs: []string{redirectURI}}}
	})
	ctx := context.Background()
	t.clients.EXPECT().FindByClientID(ctx, clientID).Return(confidentialClient(), nil)

	err := t.svc.Seed(ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "registered through the admin API")
}

func (s *IDPServiceSuite) TestSeedReportsAnInvalidClient() {
	t := s.setup(func(settings *services.Settings) {
		settings.SeedClients = []config.IDPClientConfig{{ClientID: clientID, Secret: clientSecret, Name: "Dashboard", RedirectURIs: []string{"http://dashboard.example.com/cb"}}}
	})
	err := t.svc.Seed(context.Background())
	s.Require().Error(err)
	s.Contains(err.Error(), "idp: Clients[dashboard]")
	s.Contains(err.Error(), "loopback")
}

// A client that configuration no longer declares is disabled and handed
// over to the admin API.
func (s *IDPServiceSuite) TestSeedReleasesAnUndeclaredClient() {
	t := s.setup()
	ctx := context.Background()
	orphan := confidentialClient()
	orphan.Managed = true
	t.clients.EXPECT().List(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, opts models.IDPClientListOpts) ([]*models.IDPClient, int64, error) {
		s.Require().NotNil(opts.Managed)
		s.True(*opts.Managed)
		return []*models.IDPClient{orphan}, 1, nil
	})
	t.clients.EXPECT().Update(ctx, orphan).Return(nil)

	s.Require().NoError(t.svc.Seed(ctx))
	s.True(orphan.Disabled)
	s.False(orphan.Managed)
}

// --- Admin ---

func (s *IDPServiceSuite) TestAdminCreateClientReportsATakenClientID() {
	t := s.setup()
	ctx := context.Background()
	t.clients.EXPECT().Create(ctx, gomock.Any()).Return(models.ErrConflict)

	client, authErr := t.svc.AdminCreateClient(ctx, "admin-1", &dto.ClientRequest{ClientID: clientID, Name: "Dashboard", RedirectURIs: []string{redirectURI}})
	s.Nil(client)
	s.Require().NotNil(authErr)
	s.Equal(types.ErrIDPClientExists, authErr.Code)
	s.Equal(http.StatusConflict, authErr.StatusCode)
}

func (s *IDPServiceSuite) TestAdminCreateClientGeneratesIDAndSecret() {
	t := s.setup()
	ctx := context.Background()
	var stored *models.IDPClient
	t.clients.EXPECT().Create(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, client *models.IDPClient) error {
		stored = client
		return nil
	})
	t.events.EXPECT().EmitAsync(ctx, types.EventIDPClientCreated, gomock.Any()).Return(nil)

	client, authErr := t.svc.AdminCreateClient(ctx, "admin-1", &dto.ClientRequest{Name: "Dashboard", RedirectURIs: []string{redirectURI}})
	s.Nil(authErr)
	s.Require().NotNil(client)
	s.NotEmpty(client.ClientID)
	s.GreaterOrEqual(len(client.ClientSecret), 43, "32 random bytes")
	s.Equal(services.ClientSecretDigest(client.ClientSecret), stored.SecretHash)
	s.False(stored.Managed)
	s.True(stored.RequirePKCE)
}

func (s *IDPServiceSuite) TestAdminDeleteRefusesAManagedClient() {
	t := s.setup()
	ctx := context.Background()
	managed := confidentialClient()
	managed.Managed = true
	t.clients.EXPECT().FindByID(ctx, managed.ID).Return(managed, nil)

	authErr := t.svc.AdminDeleteClient(ctx, "admin-1", managed.ID)
	s.Require().NotNil(authErr)
	s.Equal(types.ErrIDPClientManaged, authErr.Code)
}

func (s *IDPServiceSuite) TestAdminGetClientNotFound() {
	t := s.setup()
	ctx := context.Background()
	t.clients.EXPECT().FindByID(ctx, "missing").Return(nil, models.ErrNotFound)

	client, authErr := t.svc.AdminGetClient(ctx, "missing")
	s.Nil(client)
	s.Require().NotNil(authErr)
	s.Equal(types.ErrIDPClientNotFound, authErr.Code)
}

// --- Token endpoint ---

func (s *IDPServiceSuite) TestTokenRejectsRepeatedParameters() {
	t := s.setup()
	_, authErr := t.svc.Token(context.Background(), &services.TokenRequest{Form: url.Values{"grant_type": {"authorization_code", "refresh_token"}}})
	s.Require().NotNil(authErr)
	s.Equal(services.CodeInvalidRequest, authErr.Code)
}

// A user the host's policy no longer lets refresh a session gets no new
// tokens for another application either, and the refresh token is not spent.
func (s *IDPServiceSuite) TestRefreshDeniedByAuthenticationPolicy() {
	t := s.setup()
	ctx := context.Background()
	user := testutil.TestUser()
	const raw = "refresh-token-value"
	t.interceptors.Register("policy", func(_ context.Context, params *types.InterceptParams) (*types.InterceptResult, error) {
		s.Equal(types.PhaseRefresh, params.Phase)
		s.Equal([]string{"password"}, params.VerifiedMethods)
		return nil, errors.New("no longer a member")
	}, 10)

	t.clients.EXPECT().FindByClientID(ctx, clientID).Return(confidentialClient(), nil)
	t.tokens.EXPECT().FindByToken(ctx, security.TokenDigest(raw)).Return(storedToken(models.TokenTypeIDPRefresh, raw, user, "openid", "offline_access"), nil)
	t.grants.EXPECT().FindByID(ctx, "grant-1").Return(&models.IDPGrant{ID: "grant-1", UserID: user.ID, ClientID: clientID}, nil)
	t.users.EXPECT().FindByID(ctx, user.ID).Return(user, nil)

	response, authErr := t.svc.Token(ctx, refreshForm(raw))
	s.Nil(response)
	s.Require().NotNil(authErr)
	s.Equal(services.CodeInvalidGrant, authErr.Code)
}

// A challenge would need the user, whom a token request cannot ask.
func (s *IDPServiceSuite) TestRefreshDeniedWhenPolicyWantsAChallenge() {
	t := s.setup()
	ctx := context.Background()
	user := testutil.TestUser()
	const raw = "refresh-token-value"
	t.interceptors.Register("twofactor", func(context.Context, *types.InterceptParams) (*types.InterceptResult, error) {
		return &types.InterceptResult{Challenge: &types.LoginChallenge{Type: types.ChallengeTwoFactor}}, nil
	}, 10)

	t.clients.EXPECT().FindByClientID(ctx, clientID).Return(confidentialClient(), nil)
	t.tokens.EXPECT().FindByToken(ctx, security.TokenDigest(raw)).Return(storedToken(models.TokenTypeIDPRefresh, raw, user, "openid", "offline_access"), nil)
	t.grants.EXPECT().FindByID(ctx, "grant-1").Return(&models.IDPGrant{ID: "grant-1", UserID: user.ID, ClientID: clientID}, nil)
	t.users.EXPECT().FindByID(ctx, user.ID).Return(user, nil)

	_, authErr := t.svc.Token(ctx, refreshForm(raw))
	s.Require().NotNil(authErr)
	s.Equal(services.CodeInvalidGrant, authErr.Code)
}

// An access token is not a refresh token, whatever the client says.
func (s *IDPServiceSuite) TestRefreshRejectsAnAccessToken() {
	t := s.setup()
	ctx := context.Background()
	const raw = "access-token-value"
	t.clients.EXPECT().FindByClientID(ctx, clientID).Return(confidentialClient(), nil)
	t.tokens.EXPECT().FindByToken(ctx, security.TokenDigest(raw)).Return(storedToken(models.TokenTypeIDPAccess, raw, testutil.TestUser(), "openid"), nil)

	_, authErr := t.svc.Token(ctx, refreshForm(raw))
	s.Require().NotNil(authErr)
	s.Equal(services.CodeInvalidGrant, authErr.Code)
}

// --- UserInfo ---

func (s *IDPServiceSuite) TestUserInfoRejectsARefreshToken() {
	t := s.setup()
	ctx := context.Background()
	const raw = "refresh-token-value"
	t.tokens.EXPECT().FindByToken(ctx, security.TokenDigest(raw)).Return(storedToken(models.TokenTypeIDPRefresh, raw, testutil.TestUser(), "openid"), nil)

	claims, authErr := t.svc.UserInfo(ctx, raw)
	s.Nil(claims)
	s.Require().NotNil(authErr)
	s.Equal(services.CodeInvalidToken, authErr.Code)
	s.Equal(http.StatusUnauthorized, authErr.StatusCode)
}

func (s *IDPServiceSuite) TestUserInfoRejectsAnExpiredToken() {
	t := s.setup()
	ctx := context.Background()
	const raw = "access-token-value"
	record := storedToken(models.TokenTypeIDPAccess, raw, testutil.TestUser(), "openid")
	record.ExpiresAt = time.Now().Add(-time.Second)
	t.tokens.EXPECT().FindByToken(ctx, security.TokenDigest(raw)).Return(record, nil)

	_, authErr := t.svc.UserInfo(ctx, raw)
	s.Require().NotNil(authErr)
	s.Equal(services.CodeInvalidToken, authErr.Code)
}

func (s *IDPServiceSuite) TestUserInfoRejectsATokenWhoseClientIsDisabled() {
	t := s.setup()
	ctx := context.Background()
	user := testutil.TestUser()
	const raw = "access-token-value"
	disabled := confidentialClient()
	disabled.Disabled = true
	t.tokens.EXPECT().FindByToken(ctx, security.TokenDigest(raw)).Return(storedToken(models.TokenTypeIDPAccess, raw, user, "openid"), nil)
	t.grants.EXPECT().FindByID(ctx, "grant-1").Return(&models.IDPGrant{ID: "grant-1", UserID: user.ID, ClientID: clientID}, nil)
	t.clients.EXPECT().FindByClientID(ctx, clientID).Return(disabled, nil)

	_, authErr := t.svc.UserInfo(ctx, raw)
	s.Require().NotNil(authErr)
	s.Equal(services.CodeInvalidToken, authErr.Code)
}

// A failing claims function fails the request; its error is not shown.
func (s *IDPServiceSuite) TestUserInfoHidesAClaimsFunctionFailure() {
	t := s.setup(func(settings *services.Settings) {
		settings.Claims = func(context.Context, config.IDPClaimsRequest) (map[string]interface{}, error) {
			return nil, errors.New("directory unreachable at 10.0.0.5")
		}
	})
	ctx := context.Background()
	user := testutil.TestUser()
	const raw = "access-token-value"
	t.tokens.EXPECT().FindByToken(ctx, security.TokenDigest(raw)).Return(storedToken(models.TokenTypeIDPAccess, raw, user, "openid"), nil)
	t.grants.EXPECT().FindByID(ctx, "grant-1").Return(&models.IDPGrant{ID: "grant-1", UserID: user.ID, ClientID: clientID}, nil)
	t.clients.EXPECT().FindByClientID(ctx, clientID).Return(confidentialClient(), nil)
	t.users.EXPECT().FindByID(ctx, user.ID).Return(user, nil)

	claims, authErr := t.svc.UserInfo(ctx, raw)
	s.Nil(claims)
	s.Require().NotNil(authErr)
	s.Equal(services.CodeServerError, authErr.Code)
	s.NotContains(authErr.Message, "10.0.0.5")
}

// The claims function gets a copy of the user: it cannot change what the
// module stores or issues.
func (s *IDPServiceSuite) TestClaimsFunctionGetsACopyOfTheUser() {
	t := s.setup(func(settings *services.Settings) {
		settings.Claims = func(_ context.Context, request config.IDPClaimsRequest) (map[string]interface{}, error) {
			request.User.Email = "changed@example.com"
			request.Scopes[0] = "changed"
			return map[string]interface{}{"groups": []string{"staff"}}, nil
		}
	})
	ctx := context.Background()
	user := testutil.TestUser()
	const raw = "access-token-value"
	t.tokens.EXPECT().FindByToken(ctx, security.TokenDigest(raw)).Return(storedToken(models.TokenTypeIDPAccess, raw, user, "openid", "email"), nil)
	t.grants.EXPECT().FindByID(ctx, "grant-1").Return(&models.IDPGrant{ID: "grant-1", UserID: user.ID, ClientID: clientID}, nil)
	t.clients.EXPECT().FindByClientID(ctx, clientID).Return(confidentialClient(), nil)
	t.users.EXPECT().FindByID(ctx, user.ID).Return(user, nil)

	claims, authErr := t.svc.UserInfo(ctx, raw)
	s.Nil(authErr)
	s.Equal("test@example.com", claims["email"])
	s.Equal("test@example.com", user.Email)
	s.Equal([]string{"staff"}, claims["groups"])
	s.Equal(user.ID, claims["sub"])
}

// --- Grants ---

// Another user's grant is answered like one that does not exist, and is
// left alone.
func (s *IDPServiceSuite) TestRevokeGrantOfAnotherUser() {
	t := s.setup()
	ctx := context.Background()
	t.grants.EXPECT().FindByID(ctx, "grant-1").Return(&models.IDPGrant{ID: "grant-1", UserID: "someone-else", ClientID: clientID}, nil)

	authErr := t.svc.RevokeGrant(ctx, "user-1", "grant-1", nil)
	s.Require().NotNil(authErr)
	s.Equal(types.ErrIDPGrantNotFound, authErr.Code)
	s.Equal(http.StatusNotFound, authErr.StatusCode)
}

func (s *IDPServiceSuite) TestListGrantsNamesTheApplications() {
	t := s.setup()
	ctx := context.Background()
	t.grants.EXPECT().List(ctx, gomock.Any()).DoAndReturn(func(_ context.Context, opts models.IDPGrantListOpts) ([]*models.IDPGrant, int64, error) {
		s.Equal("user-1", opts.UserID, "a user only ever lists their own grants")
		return []*models.IDPGrant{
			{ID: "grant-1", UserID: "user-1", ClientID: clientID, Scopes: models.StringList{"openid"}},
			{ID: "grant-2", UserID: "user-1", ClientID: "removed-app", Scopes: models.StringList{"openid"}},
		}, 2, nil
	})
	t.clients.EXPECT().FindByClientIDs(ctx, []string{clientID, "removed-app"}).Return([]*models.IDPClient{confidentialClient()}, nil)

	grants, total, authErr := t.svc.ListGrants(ctx, "user-1", models.IDPGrantListOpts{UserID: "someone-else"})
	s.Nil(authErr)
	s.EqualValues(2, total)
	s.Require().Len(grants, 2)
	s.Equal("Dashboard", grants[0].ClientName)
	s.Equal("removed-app", grants[1].ClientName, "an application that is gone is shown by its identifier")
}

func (s *IDPServiceSuite) TestDiscoveryStatesOnlyWhatIsSupported() {
	t := s.setup()
	document := t.svc.Discovery()
	s.Equal(t.settings.Issuer, document.Issuer)
	s.Equal([]string{"code"}, document.ResponseTypesSupported)
	s.Equal([]string{"RS256"}, document.IDTokenSigningAlgValuesSupported)
	s.Equal([]string{"S256"}, document.CodeChallengeMethodsSupported)
	s.ElementsMatch([]string{"authorization_code", "refresh_token"}, document.GrantTypesSupported)
	s.False(document.RequestParameterSupported)
	s.False(document.ClaimsParameterSupported)
	s.Len(t.svc.JWKS().Keys, 1)
}
