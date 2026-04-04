package services

import (
	"context"
	"errors"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Logout invalidates the current session
func (s *sessionService) Logout(ctx context.Context, userID, sessionID string) *types.GoAuthError {
	session, err := s.sessionRepository.FindByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewSessionNotFoundError()
		}
		return types.NewInternalError("failed to find session").Wrap(err)
	}

	if session.UserID != userID {
		return types.NewUnauthorizedError()
	}

	if err := s.sessionRepository.Delete(ctx, sessionID); err != nil {
		return types.NewInternalError("failed to delete session").Wrap(err)
	}

	return nil
}
