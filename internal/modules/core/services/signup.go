package core_services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// Signup creates a new user account
// Note: This only creates the user. Authentication (tokens/sessions) is handled by auth modules (session or stateless)
func (s *CoreService) Signup(ctx context.Context, req *dto.SignupRequest) (*dto.AuthResponse, *types.GoAuthError) {
	// Check if user already exists
	if req.Email != "" {
		existing, _ := s.UserRepository.FindByEmail(ctx, req.Email)
		if existing != nil {
			return nil, types.NewUserAlreadyExistsError()
		}
	}
	if req.Username != "" {
		existing, _ := s.UserRepository.FindByUsername(ctx, req.Username)
		if existing != nil {
			return nil, types.NewUsernameAlreadyExistsError()
		}
	}
	if req.PhoneNumber != "" && s.Config.UniquePhoneNumber {
		existing, _ := s.UserRepository.FindByPhoneNumber(ctx, req.PhoneNumber)
		if existing != nil {
			return nil, types.NewPhoneAlreadyInUseError()
		}
	}

	// Hash password
	hashedPassword, err := s.SecurityManager.HashPassword(req.Password)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to hash password: %v", err.Error()))
	}

	now := time.Now()
	// Create user
	user := &models.User{
		ID:           uuid.New().String(),
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
		return nil, types.NewInternalError(fmt.Sprintf("failed to create user: %v", err.Error()))
	}

	// Set extended attributes if provided
	if req.ExtendedAttributes != nil {
		for _, attr := range req.ExtendedAttributes {
			_ = s.setAttribute(ctx, user.ID, attr.Name, attr.Value)
		}
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
		ExtendedAttributes: func() []dto.ExtendedAttributes {
			attrs := make([]dto.ExtendedAttributes, len(user.ExtendedAttributes))
			for i, attr := range user.ExtendedAttributes {
				attrs[i] = dto.ExtendedAttributes{Name: attr.Name, Value: attr.Value}
			}
			return attrs
		}(),
	}

	// Return user data only - authentication is handled by auth modules (session or stateless)
	authResponse := &dto.AuthResponse{
		User:    userDto,
		Message: s.signupMessage(user),
	}

	return authResponse, nil
}

func (s *CoreService) signupMessage(user *models.User) string {
	if s.Config.RequireEmailVerification && user.Email != "" && !user.EmailVerified {
		return "Signup successful. Please verify your email to continue."
	}
	if s.Config.RequirePhoneVerification && user.PhoneNumber != "" && !user.PhoneNumberVerified {
		return "Signup successful. Please verify your phone to continue."
	}
	return "Signup successful. Please login to continue."
}

func (s *CoreService) generateRandomUsername(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0] + "-" + uuid.New().String()[:8]
	}
	return "user-" + uuid.New().String()[:8]
}
