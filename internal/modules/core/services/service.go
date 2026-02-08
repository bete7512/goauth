package core_services

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

//go:generate mockgen -destination=../../../mocks/mock_core_service.go -package=mocks github.com/bete7512/goauth/internal/modules/core/services CoreService

// CoreService defines the core authentication service operations.
type CoreService interface {
	Signup(ctx context.Context, req *dto.SignupRequest) (*dto.AuthResponse, *types.GoAuthError)
	GetCurrentUser(ctx context.Context, userID string) (*dto.UserDTO, *types.GoAuthError)
	GetProfile(ctx context.Context, userID string) (*dto.UserDTO, *types.GoAuthError)
	UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserDTO, *types.GoAuthError)
	ChangePassword(ctx context.Context, userID string, req *dto.ChangePasswordRequest) (*dto.MessageResponse, *types.GoAuthError)
	ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) (*dto.MessageResponse, *types.GoAuthError)
	ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) (*dto.MessageResponse, *types.GoAuthError)
	CheckEmailAvailability(ctx context.Context, email string) (*dto.CheckAvailabilityResponse, *types.GoAuthError)
	CheckUsernameAvailability(ctx context.Context, username string) (*dto.CheckAvailabilityResponse, *types.GoAuthError)
	CheckPhoneAvailability(ctx context.Context, phone string) (*dto.CheckAvailabilityResponse, *types.GoAuthError)
}

type coreService struct {
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
) *coreService {
	return &coreService{
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

func (s *coreService) setAttribute(ctx context.Context, userID string, name string, value string) error {
	if s.UserExtendedAttributeRepository == nil {
		return nil
	}
	return s.UserExtendedAttributeRepository.Upsert(ctx, userID, name, value)
}
