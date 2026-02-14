package services

import (
	"context"

	"github.com/bete7512/goauth/pkg/types"
)

// Logout invalidates the current session
func (s *sessionService) Logout(ctx context.Context, userID, sessionID string) *types.GoAuthError {
	session, err := s.sessionRepository.FindByID(ctx, sessionID)
	if err != nil || session == nil {
		return types.NewSessionNotFoundError()
	}

	if session.UserID != userID {
		return types.NewUnauthorizedError()
	}

	if err := s.sessionRepository.Delete(ctx, sessionID); err != nil {
		return types.NewInternalError("Failed to delete session")
	}

	return nil
}
