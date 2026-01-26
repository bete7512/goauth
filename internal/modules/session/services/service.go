package services

import (
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
)

type SessionService struct {
	Deps              config.ModuleDependencies
	Config            *config.SessionModuleConfig
	UserRepository    models.UserRepository
	SessionRepository models.SessionRepository
	Logger            logger.Logger
	SecurityManager   *security.SecurityManager
}

func NewSessionService(
	deps config.ModuleDependencies,
	userRepository models.UserRepository,
	sessionRepository models.SessionRepository,
	logger logger.Logger,
	securityManager *security.SecurityManager,
	cfg *config.SessionModuleConfig,
) *SessionService {
	return &SessionService{
		Deps:              deps,
		UserRepository:    userRepository,
		SessionRepository: sessionRepository,
		Logger:            logger,
		SecurityManager:   securityManager,
		Config:            cfg,
	}
}
