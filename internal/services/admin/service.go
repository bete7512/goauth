package admin_service

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type AdminService struct {
	userRepo    interfaces.UserRepository
	tokenRepo   interfaces.TokenRepository
	tokenMgr    interfaces.TokenManagerInterface
	sessionRepo interfaces.SessionRepository
	logger      interfaces.Logger
	config      *config.Auth
}

var _ interfaces.AdminService = (*AdminService)(nil)

func NewAdminService(
	userRepo interfaces.UserRepository,
	sessionRepo interfaces.SessionRepository,
	tokenRepo interfaces.TokenRepository,
	tokenMgr interfaces.TokenManagerInterface,
	logger interfaces.Logger,
) *AdminService {
	return &AdminService{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		tokenMgr:    tokenMgr,
		sessionRepo: sessionRepo,
		logger:      logger,
	}
}
