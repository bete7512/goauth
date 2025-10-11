package core_services

import (
	"context"

	coreConfig "github.com/bete7512/goauth/internal/modules/core/config"
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
)

type CoreService struct {
	Deps                             config.ModuleDependencies
	Config                           *coreConfig.Config
	UserRepository                   models.UserRepository
	UserExtendedAttributesRepository models.ExtendedAttributesRepository
	SessionRepository                models.SessionRepository
	TokenRepository                  models.TokenRepository
	VerificationTokenRepository      models.VerificationTokenRepository
	Logger                           logger.Logger
	SecurityManager                  *security.SecurityManager
}

func NewCoreService(deps config.ModuleDependencies, userRepository models.UserRepository, userAttrRepo models.ExtendedAttributesRepository, sessionRepository models.SessionRepository, tokenRepository models.TokenRepository, verificationTokenRepository models.VerificationTokenRepository, logger logger.Logger, securityManager *security.SecurityManager, config *coreConfig.Config) *CoreService {

	return &CoreService{
		Deps:                             deps,
		UserRepository:                   userRepository,
		UserExtendedAttributesRepository: userAttrRepo,
		SessionRepository:                sessionRepository,
		TokenRepository:                  tokenRepository,
		VerificationTokenRepository:      verificationTokenRepository,
		Logger:                           deps.Logger,
		SecurityManager:                  securityManager,
		Config:                           config,
	}
}

func (s *CoreService) getAttribute(ctx context.Context, userID string, name string) (string, error) {
	if s.UserExtendedAttributesRepository == nil {
		return "", nil
	}
	attr, err := s.UserExtendedAttributesRepository.FindByUserAndName(ctx, userID, name)
	if err != nil || attr == nil {
		return "", err
	}
	return attr.Value, nil
}

func (s *CoreService) setAttribute(ctx context.Context, userID string, name string, value string) error {
	if s.UserExtendedAttributesRepository == nil {
		return nil
	}
	return s.UserExtendedAttributesRepository.Upsert(ctx, userID, name, value)
}

func (s *CoreService) setAttributes(ctx context.Context, userID string, attrs []models.ExtendedAttributes) error {
	if s.UserExtendedAttributesRepository == nil {
		return nil
	}
	return s.UserExtendedAttributesRepository.UpsertMany(ctx, attrs)
}
