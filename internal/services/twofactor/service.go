package twofactor_service

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type TwoFactorService struct {
	tokenRepo interfaces.TokenRepository
	
	userRepo  interfaces.UserRepository
	tokenMgr  interfaces.TokenManagerInterface
	logger    interfaces.Logger
	config    *config.Auth
}

var _ interfaces.TwoFactorService = (*TwoFactorService)(nil)

func NewTwoFactorService(
	tokenRepo interfaces.TokenRepository,
	userRepo interfaces.UserRepository,
	tokenMgr interfaces.TokenManagerInterface,
	logger interfaces.Logger,
	config *config.Auth,
) *TwoFactorService {
	return &TwoFactorService{
		tokenRepo: tokenRepo,
		userRepo:  userRepo,
		tokenMgr:  tokenMgr,
		logger:    logger,
		config:    config,
	}
}
