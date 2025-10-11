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
	user, err = s.UserRepository.FindByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return nil, types.NewInvalidCredentialsError()
	}
	if s.Config.RequireEmailVerification && user.Email != "" && !user.EmailVerified {
		return nil, types.NewEmailNotVerifiedError()
	}
	if s.Config.RequirePhoneVerification && user.PhoneNumber != "" && !user.PhoneNumberVerified {
		return nil, types.NewPhoneNotVerifiedError()
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, types.NewInvalidCredentialsError()
	}

	// Generate session token
	sessionToken, err := s.Deps.SecurityManager.GenerateRandomToken(32)
	if err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to generate session token: %w", err))
	}

	// Create session
	session := &models.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(s.Deps.Config.Security.Session.SessionDuration), // 24 hours
		CreatedAt: time.Now(),
	}

	if err := s.SessionRepository.Create(ctx, session); err != nil {
		return nil, types.NewInternalError(fmt.Sprintf("failed to create session: %w", err))
	}

	// Update last login
	user.UpdatedAt = time.Now()
	s.UserRepository.Update(ctx, user)

	// Emit after login event
	s.Deps.Events.EmitAsync(ctx, types.EventAfterLogin, map[string]interface{}{
		"user":       user,
		"ip_address": ctx.Value("ip_address"),
		"timestamp":  time.Now().Format("2006-01-02 15:04:05"),
	})

	return &dto.AuthResponse{
		Token: sessionToken,
		User: &dto.UserDTO{
			ID:                  user.ID,
			Email:               user.Email,
			Username:            user.Username,
			Name:                user.Name,
			FirstName:           user.FirstName,
			LastName:            user.LastName,
			PhoneNumber:         user.PhoneNumber,
			Active:              true,
			EmailVerified:       user.EmailVerified,
			PhoneNumberVerified: user.PhoneNumberVerified,
			CreatedAt:           user.CreatedAt.Format(time.RFC3339),
			UpdatedAt:           user.UpdatedAt.Format(time.RFC3339),
		},
		ExpiresIn: int64(s.Deps.Config.Security.Session.SessionDuration.Seconds()),
		Message:   "Login successful",
	}, nil
}
