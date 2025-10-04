package core_services

import (
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreService struct {
	deps                        config.ModuleDependencies
	UserRepository              models.UserRepository
	SessionRepository           models.SessionRepository
	TokenRepository             models.TokenRepository
	VerificationTokenRepository models.VerificationTokenRepository
	// Logger logger.Log
	// inject storages
	// Storage storage.Storage
}

func NewCoreService(deps config.ModuleDependencies, userRepository models.UserRepository, sessionRepository models.SessionRepository, tokenRepository models.TokenRepository, verificationTokenRepository models.VerificationTokenRepository) *CoreService {
	return &CoreService{
		deps:                        deps,
		UserRepository:              userRepository,
		SessionRepository:           sessionRepository,
		TokenRepository:             tokenRepository,
		VerificationTokenRepository: verificationTokenRepository,
	}
}

// implement service methods here
