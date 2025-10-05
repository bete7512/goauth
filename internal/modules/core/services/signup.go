package core_services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to hash password: %w", err))
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
		return nil, types.NewInternalError(fmt.Sprintf("failed to create user: %w", err))
	}

	// Generate session token
	sessionToken, err := generateSecureToken(32)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate session token: %w", err))
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
		return nil, types.NewInternalError(fmt.Sprintf("failed to create session: %w", err))
	}

	// Emit after:signup event
	s.deps.Events.Emit(ctx, "after:signup", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"name":    user.Name,
	})

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
