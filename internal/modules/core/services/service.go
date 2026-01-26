package core_services

import (
	"context"

	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
)

type CoreService struct {
	Deps                            config.ModuleDependencies
	Config                          *config.CoreConfig
	UserRepository                  models.UserRepository
	UserExtendedAttributeRepository models.ExtendedAttributeRepository
	TokenRepository                 models.TokenRepository
	VerificationTokenRepository     models.VerificationTokenRepository
	Logger                          logger.Logger
	SecurityManager                 *security.SecurityManager
}

func NewCoreService(
	deps config.ModuleDependencies,
	userRepository models.UserRepository,
	userAttrRepo models.ExtendedAttributeRepository,
	tokenRepository models.TokenRepository,
	verificationTokenRepository models.VerificationTokenRepository,
	logger logger.Logger,
	securityManager *security.SecurityManager,
	config *config.CoreConfig,
) *CoreService {
	return &CoreService{
		Deps:                            deps,
		UserRepository:                  userRepository,
		UserExtendedAttributeRepository: userAttrRepo,
		TokenRepository:                 tokenRepository,
		VerificationTokenRepository:     verificationTokenRepository,
		Logger:                          deps.Logger,
		SecurityManager:                 securityManager,
		Config:                          config,
	}
}

func (s *CoreService) setAttribute(ctx context.Context, userID string, name string, value string) error {
	if s.UserExtendedAttributeRepository == nil {
		return nil
	}
	return s.UserExtendedAttributeRepository.Upsert(ctx, userID, name, value)
}
