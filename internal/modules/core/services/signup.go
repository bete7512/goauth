package core_services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// Signup creates a new user account
// Note: This only creates the user. Authentication (tokens/sessions) is handled by auth modules (session or stateless)
func (s *coreService) Signup(ctx context.Context, req *dto.SignupRequest) (*dto.AuthResponse, *types.GoAuthError) {
	// Check if user already exists
	if req.Email != "" {
		existing, err := s.UserRepository.FindByEmail(ctx, req.Email)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, types.NewInternalError("failed to check existing user by email").Wrap(err)
		}
		if existing != nil {
			return nil, types.NewUserAlreadyExistsError()
		}
	}
	if req.Username != "" {
		existing, err := s.UserRepository.FindByUsername(ctx, req.Username)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, types.NewInternalError("failed to check existing user by username").Wrap(err)
		}
		if existing != nil {
			return nil, types.NewUsernameAlreadyExistsError()
		}
	}
	if req.PhoneNumber != "" && s.Config.UniquePhoneNumber {
		existing, err := s.UserRepository.FindByPhoneNumber(ctx, req.PhoneNumber)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, types.NewInternalError("failed to check existing user by phone").Wrap(err)
		}
		if existing != nil {
			return nil, types.NewPhoneAlreadyInUseError()
		}
	}

	// Hash password
	hashedPassword, err := s.SecurityManager.HashPassword(req.Password)
	if err != nil {
		return nil, types.NewInternalError("failed to hash password").Wrap(err)
	}

	now := time.Now()
	// Create user
	user := &models.User{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Name:         req.Name,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		PhoneNumber:  req.PhoneNumber,
		Active:       !s.Config.RequireEmailVerification && !s.Config.RequirePhoneVerification,
		CreatedAt:    now,
		UpdatedAt:    &now,
	}
	if s.Config.RequireEmailVerification {
		user.EmailVerified = false
	}
	if s.Config.RequirePhoneVerification {
		user.PhoneNumberVerified = false
	}
	if s.Config.RequireUserName {
		user.Username = req.Username
	} else {
		user.Username = s.generateRandomUsername(req.Email)
	}

	if err := s.UserRepository.Create(ctx, user); err != nil {
		return nil, types.NewInternalError("failed to create user").Wrap(err)
	}

	userDto := &dto.UserDTO{
		ID:                  user.ID,
		Email:               user.Email,
		Username:            user.Username,
		Name:                user.Name,
		FirstName:           user.FirstName,
		LastName:            user.LastName,
		PhoneNumber:         user.PhoneNumber,
		Active:              user.Active,
		EmailVerified:       user.EmailVerified,
		PhoneNumberVerified: user.PhoneNumberVerified,
		CreatedAt:           user.CreatedAt,
		UpdatedAt:           user.UpdatedAt,
		LastLoginAt:         user.LastLoginAt,
	}

	// Return user data only - authentication is handled by auth modules (session or stateless)
	authResponse := &dto.AuthResponse{
		User:    userDto,
		Message: s.signupMessage(user),
	}

	return authResponse, nil
}

func (s *coreService) signupMessage(user *models.User) string {
	if s.Config.RequireEmailVerification && user.Email != "" && !user.EmailVerified {
		return "Signup successful. Please verify your email to continue."
	}
	if s.Config.RequirePhoneVerification && user.PhoneNumber != "" && !user.PhoneNumberVerified {
		return "Signup successful. Please verify your phone to continue."
	}
	return "Signup successful. Please login to continue."
}

func (s *coreService) generateRandomUsername(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0] + "-" + uuid.Must(uuid.NewV7()).String()[:8]
	}
	return "user-" + uuid.Must(uuid.NewV7()).String()[:8]
}
