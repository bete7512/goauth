package core_services

import (
	"context"
	"encoding/hex"
	"math/rand"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/pkg/types"
)

// GetCurrentUser retrieves user from session token
func (s *CoreService) GetCurrentUser(ctx context.Context, sessionToken string) (*dto.UserDTO, *types.GoAuthError) {
	session, err := s.SessionRepository.FindByToken(ctx, sessionToken)
	if err != nil || session == nil {
		return nil, types.NewInvalidSessionError()
	}

	// Check if session expired
	if session.ExpiresAt.Before(time.Now()) {
		s.SessionRepository.Delete(ctx, session.ID)
		return nil, types.NewSessionExpiredError()
	}

	user, err := s.UserRepository.FindByID(ctx, session.UserID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	return &dto.UserDTO{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Username,
		Name:          user.Name,
		Phone:         user.Phone,
		Avatar:        user.Avatar,
		Active:        user.Active,
		EmailVerified: user.EmailVerified,
		PhoneVerified: user.PhoneVerified,
		CreatedAt:     user.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     user.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// Helper function to generate secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
