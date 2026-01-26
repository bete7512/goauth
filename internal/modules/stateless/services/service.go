package services

import (
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
)

type StatelessService struct {
	Deps            config.ModuleDependencies
	Config          *config.StatelessModuleConfig
	UserRepository  models.UserRepository
	TokenRepository models.TokenRepository
	Logger          logger.Logger
	SecurityManager *security.SecurityManager
}

func NewStatelessService(
	deps config.ModuleDependencies,
	userRepository models.UserRepository,
	tokenRepository models.TokenRepository,
	logger logger.Logger,
	securityManager *security.SecurityManager,
	cfg *config.StatelessModuleConfig,
) *StatelessService {
	return &StatelessService{
		Deps:            deps,
		UserRepository:  userRepository,
		TokenRepository: tokenRepository,
		Logger:          logger,
		SecurityManager: securityManager,
		Config:          cfg,
	}
}

