package core_services

import (
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreService struct {
	deps                        config.ModuleDependencies
	UserRepository              models.UserRepository
	SessionRepository           models.SessionRepository
	TokenRepository             models.TokenRepository
	VerificationTokenRepository models.VerificationTokenRepository
	Logger                      logger.Logger
	SecurityManager             *security.SecurityManager
}

func NewCoreService(deps config.ModuleDependencies, userRepository models.UserRepository, sessionRepository models.SessionRepository, tokenRepository models.TokenRepository, verificationTokenRepository models.VerificationTokenRepository, logger logger.Logger, securityManager *security.SecurityManager) *CoreService {
	return &CoreService{
		deps:                        deps,
		UserRepository:              userRepository,
		SessionRepository:           sessionRepository,
		TokenRepository:             tokenRepository,
		VerificationTokenRepository: verificationTokenRepository,
		Logger:                      deps.Logger,
		SecurityManager:             securityManager,
	}
}

// implement service methods here
