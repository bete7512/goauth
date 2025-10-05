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

// Login authenticates user and creates session
func (s *CoreService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.AuthResponse, *types.GoAuthError) {
	// Find user
	var user *models.User
	var err error

	if req.Email != "" {
		user, err = s.UserRepository.FindByEmail(ctx, req.Email)
	} else if req.Username != "" {
		user, err = s.UserRepository.FindByUsername(ctx, req.Username)
	} else {
		return nil, types.NewMissingFieldsError("email or username")
	}

	if err != nil || user == nil {
		return nil, types.NewInvalidCredentialsError()
	}

	// Check if account is active
	if !user.Active {
		return nil, types.NewUserNotActiveError()
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, types.NewInvalidCredentialsError()
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

	// Update last login
	user.UpdatedAt = time.Now()
	s.UserRepository.Update(ctx, user)

	// Emit after:login event
	s.deps.Events.Emit(ctx, "after:login", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
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
		Message:   "Login successful",
	}, nil
}
