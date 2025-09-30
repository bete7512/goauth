package user_service

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type UserService struct {
	userRepo    interfaces.UserRepository
	tokenRepo   interfaces.TokenRepository
	sessionRepo interfaces.SessionRepository
	tokenMgr    interfaces.TokenManagerInterface
	cache       interfaces.Cache
	logger      interfaces.Logger
	config      *config.Auth
}

var _ interfaces.UserService = (*UserService)(nil)

func NewUserService(
	userRepo interfaces.UserRepository,
	tokenRepo interfaces.TokenRepository,
	sessionRepo interfaces.SessionRepository,
	tokenMgr interfaces.TokenManagerInterface,
	cache interfaces.Cache,
	logger interfaces.Logger,
	config *config.Auth,
) *UserService {

	return &UserService{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		sessionRepo: sessionRepo,
		tokenMgr:    tokenMgr,
		cache:       cache,
		logger:      logger,
		config:      config,
	}
}
