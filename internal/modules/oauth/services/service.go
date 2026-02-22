package services

//go:generate mockgen -destination=../../../mocks/mock_oauth_service.go -package=mocks github.com/bete7512/goauth/internal/modules/oauth/services OAuthService

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/oauth/providers"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// OAuthService defines the interface for OAuth authentication operations
type OAuthService interface {
	// InitiateLogin generates state, PKCE, and returns the authorization URL
	InitiateLogin(ctx context.Context, providerName, clientRedirectURI string) (string, *types.GoAuthError)

	// HandleCallback validates state, exchanges code, and creates/links user
	HandleCallback(ctx context.Context, providerName, code, state string, metadata *types.RequestMetadata) (*OAuthResult, *types.GoAuthError)

	// UnlinkProvider removes an OAuth provider link from a user account
	UnlinkProvider(ctx context.Context, userID, providerName string) *types.GoAuthError

	// GetLinkedProviders returns the list of OAuth providers linked to a user
	GetLinkedProviders(ctx context.Context, userID string) ([]string, *types.GoAuthError)

	// ListEnabledProviders returns the list of enabled provider names
	ListEnabledProviders() []string
}

// OAuthResult contains the result of successful OAuth authentication
type OAuthResult struct {
	User                 *models.User
	AccessToken          string
	RefreshToken         string
	ExpiresIn            int64
	IsNewUser            bool
	Provider             string
	ProviderAccessToken  string
	ProviderRefreshToken string
	ClientRedirectURI    string // Client-provided redirect URI for frontend redirect
	SessionID            string // Session ID if session-based auth is used
}

// oauthService implements OAuthService
type oauthService struct {
	deps            config.ModuleDependencies
	config          *config.OAuthModuleConfig
	registry        *providers.Registry
	userRepo        models.UserRepository
	tokenRepo       models.TokenRepository
	accountRepo     models.AccountRepository
	sessionRepo     models.SessionRepository // nil if stateless mode
	securityManager types.SecurityManager
	logger          logger.Logger
	apiURL          string
	basePath        string
}

// NewOAuthService creates a new OAuth service
func NewOAuthService(
	deps config.ModuleDependencies,
	cfg *config.OAuthModuleConfig,
	registry *providers.Registry,
	userRepo models.UserRepository,
	tokenRepo models.TokenRepository,
	accountRepo models.AccountRepository,
	sessionRepo models.SessionRepository, // nil for stateless mode
	securityManager types.SecurityManager,
	apiURL, basePath string,
) *oauthService {
	return &oauthService{
		deps:            deps,
		config:          cfg,
		registry:        registry,
		userRepo:        userRepo,
		tokenRepo:       tokenRepo,
		accountRepo:     accountRepo,
		sessionRepo:     sessionRepo,
		securityManager: securityManager,
		logger:          deps.Logger,
		apiURL:          apiURL,
		basePath:        basePath,
	}
}

// useSessionAuth returns true if session-based auth is configured and available
func (s *oauthService) useSessionAuth() bool {
	return s.config.UseSessionAuth && s.sessionRepo != nil
}
