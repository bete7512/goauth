package auth_service

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type AuthService struct {
	userRepo    interfaces.UserRepository
	tokenRepo   interfaces.TokenRepository
	sessionRepo interfaces.SessionRepository
	tokenMgr    interfaces.TokenManagerInterface
	cache       interfaces.Cache
	logger      interfaces.Logger
	config      *config.Auth
}

var _ interfaces.AuthService = (*AuthService)(nil)

func NewAuthService(
	userRepo interfaces.UserRepository,
	tokenRepo interfaces.TokenRepository,
	sessionRepo interfaces.SessionRepository,
	tokenMgr interfaces.TokenManagerInterface,
	cache interfaces.Cache,
	logger interfaces.Logger,
	config *config.Auth,
) interfaces.AuthService {
	return &AuthService{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		sessionRepo: sessionRepo,
		tokenMgr:    tokenMgr,
		cache:       cache,
		logger:      logger,
		config:      config,
	}
}
