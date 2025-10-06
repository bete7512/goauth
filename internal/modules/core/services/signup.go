package core_services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// Signup creates a new user account
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
			return nil, types.NewUserAlreadyExistsError()
		}
	}

	if req.Phone != "" {
		existing, _ := s.UserRepository.FindByPhone(ctx, req.Phone)
		if existing != nil {
			return nil, types.NewUserAlreadyExistsError()
		}
	}

	if s.SecurityManager == nil {
		return nil, types.NewInternalError("security manager is nil")
	}
	// Hash password
	hashedPassword, err := s.SecurityManager.HashPassword(req.Password)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to hash password: %v", err.Error()))
	}

	// Create user
	user := &models.User{
		ID:           uuid.New().String(),
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		Name:         req.Name,
		Phone:        req.Phone,
		Active:       true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.UserRepository.Create(ctx, user); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create user: %v", err.Error()))
	}

	// Generate session token
	sessionToken, err := s.deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate session token: %v", err.Error()))
	}

	// Create session
	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours
		CreatedAt: time.Now(),
	}

	if err := s.SessionRepository.Create(ctx, session); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create session: %v", err.Error()))
	}

	return &dto.AuthResponse{
		Token: sessionToken,
		User: &dto.UserDTO{
			ID:            user.ID,
			Email:         user.Email,
			Username:      user.Username,
			Name:          user.Name,
			Phone:         user.Phone,
			Active:        user.Active,
			EmailVerified: user.EmailVerified,
			PhoneVerified: user.PhoneVerified,
			CreatedAt:     user.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     user.UpdatedAt.Format(time.RFC3339),
		},
		ExpiresIn: 86400, // 24 hours in seconds
		Message:   "Signup successful",
	}, nil
}
