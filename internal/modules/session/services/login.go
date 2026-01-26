package services

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// LoginMetadata contains additional information about the login request
type LoginMetadata struct {
	IPAddress string
	UserAgent string
}

// Login authenticates user and creates session
func (s *SessionService) Login(ctx context.Context, req *dto.LoginRequest, metadata *LoginMetadata) (dto.AuthResponse, *types.GoAuthError) {
	// Find user
	user, err := s.UserRepository.FindByEmail(ctx, req.Email)
	if err != nil || user == nil {
		// Try by username if email not found
		if req.Username != "" {
			user, err = s.UserRepository.FindByUsername(ctx, req.Username)
		}
		if err != nil || user == nil {
			return dto.AuthResponse{}, types.NewInvalidCredentialsError()
		}
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return dto.AuthResponse{}, types.NewInvalidCredentialsError()
	}

	// Generate tokens
	accessToken, refreshToken, err := s.SecurityManager.GenerateTokens(user, map[string]interface{}{})
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to generate tokens: %s", err.Error()))
	}

	// Create session
	session := &models.Session{
		ID:                    uuid.New().String(),
		UserID:                user.ID,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: time.Now().Add(s.Deps.Config.Security.Session.RefreshTokenTTL),
		ExpiresAt:             time.Now().Add(s.Deps.Config.Security.Session.SessionTTL),
		UserAgent:             metadata.UserAgent,
		IPAddress:             metadata.IPAddress,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	if err := s.SessionRepository.Create(ctx, session); err != nil {
		return dto.AuthResponse{}, types.NewInternalError(fmt.Sprintf("failed to create session: %s", err.Error()))
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.UserRepository.Update(ctx, user); err != nil {
		s.Logger.Errorf("failed to update user last login time: %v", err)
	}

	return dto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
		User:         dto.UserToDTO(user),
		ExpiresIn:    int64(s.Deps.Config.Security.Session.SessionTTL.Seconds()),
		Message:      "Login successful",
	}, nil
}
