package services

//go:generate mockgen -destination=../../../mocks/mock_saml_service.go -package=mocks github.com/bete7512/goauth/internal/modules/saml/services SAMLService

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/saml/providers"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// SAMLService drives the service-provider side of SAML 2.0 Web Browser SSO.
type SAMLService interface {
	// InitiateLogin records an AuthnRequest and returns the IdP redirect URL
	// together with the request ID that binds the browser to the response.
	InitiateLogin(ctx context.Context, providerName, clientRedirectURI string) (*LoginStart, *types.GoAuthError)

	// HandleACS verifies the SAMLResponse posted to the Assertion Consumer
	// Service, provisions or links the user and completes authentication.
	// relayState is the request ID echoed by the IdP; it is empty for
	// IdP-initiated logins.
	HandleACS(ctx context.Context, providerName, relayState string, r *http.Request, metadata *types.RequestMetadata) (*SAMLResult, *types.GoAuthError)

	// Metadata returns the SP metadata document for a connection.
	Metadata(providerName string) ([]byte, *types.GoAuthError)

	// ListProviders returns the configured connection names.
	ListProviders() []string
}

// LoginStart is the outcome of InitiateLogin.
type LoginStart struct {
	RedirectURL string
	RequestID   string
}

// SAMLResult contains the result of a successful SAML login.
type SAMLResult struct {
	User              *models.User
	AccessToken       string
	RefreshToken      string
	ExpiresIn         int64
	IsNewUser         bool
	Provider          string
	NameID            string
	ClientRedirectURI string
	SessionID         string
	Challenges        []types.LoginChallenge
}

// samlService implements SAMLService.
type samlService struct {
	inTransaction   bool
	deps            config.ModuleDependencies
	config          *config.SAMLModuleConfig
	registry        *providers.Registry
	userRepo        models.UserRepository
	tokenRepo       models.TokenRepository
	accountRepo     models.AccountRepository
	sessionRepo     models.SessionRepository // nil in stateless mode
	securityManager types.SecurityManager
	logger          types.Logger
}

// NewSAMLService creates the SAML service.
func NewSAMLService(
	deps config.ModuleDependencies,
	cfg *config.SAMLModuleConfig,
	registry *providers.Registry,
	userRepo models.UserRepository,
	tokenRepo models.TokenRepository,
	accountRepo models.AccountRepository,
	sessionRepo models.SessionRepository,
	securityManager types.SecurityManager,
) *samlService {
	return &samlService{
		deps:            deps,
		config:          cfg,
		registry:        registry,
		userRepo:        userRepo,
		tokenRepo:       tokenRepo,
		accountRepo:     accountRepo,
		sessionRepo:     sessionRepo,
		securityManager: securityManager,
		logger:          deps.Logger,
	}
}

func (s *samlService) useSessionAuth() bool {
	return s.config.UseSessionAuth && s.sessionRepo != nil
}
