package core_services

import (
	"context"
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
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Avatar:    user.Avatar,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}
