package oauth_service

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type OAuthService struct {
	userRepo    interfaces.UserRepository
	tokenRepo   interfaces.TokenRepository
	tokenMgr    interfaces.TokenManagerInterface
	sessionRepo interfaces.SessionRepository
	logger      interfaces.Logger
	config      *config.Auth
}

var _ interfaces.OAuthService = (*OAuthService)(nil)

func NewOAuthService(
	userRepo interfaces.UserRepository,
	tokenRepo interfaces.TokenRepository,
	tokenMgr interfaces.TokenManagerInterface,
	sessionRepo interfaces.SessionRepository,
	logger interfaces.Logger,
	config *config.Auth,
) *OAuthService {
	return &OAuthService{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		tokenMgr:    tokenMgr,
		sessionRepo: sessionRepo,
		logger:      logger,
		config:      config,
	}
}
