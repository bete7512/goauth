package core_services

import (
	"context"

	notification_models "github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreService struct {
	Deps                            config.ModuleDependencies
	Config                          *config.CoreConfig
	UserRepository                  models.UserRepository
	UserExtendedAttributeRepository models.ExtendedAttributeRepository
	SessionRepository               models.SessionRepository
	TokenRepository                 models.TokenRepository
	VerificationTokenRepository     notification_models.VerificationTokenRepository
	Logger                          logger.Logger
	SecurityManager                 *security.SecurityManager
}

func NewCoreService(deps config.ModuleDependencies, userRepository models.UserRepository, userAttrRepo models.ExtendedAttributeRepository, sessionRepository models.SessionRepository, tokenRepository models.TokenRepository, verificationTokenRepository notification_models.VerificationTokenRepository, logger logger.Logger, securityManager *security.SecurityManager, config *config.CoreConfig) *CoreService {

	return &CoreService{
		Deps:                            deps,
		UserRepository:                  userRepository,
		UserExtendedAttributeRepository: userAttrRepo,
		SessionRepository:               sessionRepository,
		TokenRepository:                 tokenRepository,
		VerificationTokenRepository:     verificationTokenRepository,
		Logger:                          deps.Logger,
		SecurityManager:                 securityManager,
		Config:                          config,
	}
}

func (s *CoreService) getAttribute(ctx context.Context, userID string, name string) (string, error) {
	if s.UserExtendedAttributeRepository == nil {
		return "", nil
	}
	attr, err := s.UserExtendedAttributeRepository.FindByUserAndName(ctx, userID, name)
	if err != nil || attr == nil {
		return "", err
	}
	return attr.Value, nil
}

func (s *CoreService) setAttribute(ctx context.Context, userID string, name string, value string) error {
	if s.UserExtendedAttributeRepository == nil {
		return nil
	}
	return s.UserExtendedAttributeRepository.Upsert(ctx, userID, name, value)
}

func (s *CoreService) setAttributes(ctx context.Context, userID string, attrs []models.ExtendedAttributes) error {
	if s.UserExtendedAttributeRepository == nil {
		return nil
	}
	return s.UserExtendedAttributeRepository.UpsertMany(ctx, attrs)
}
