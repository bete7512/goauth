package services

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Logout invalidates user session(s)
func (s *SessionService) Logout(ctx context.Context, userID string) *types.GoAuthError {
	sessions, _, err := s.SessionRepository.FindByUserID(ctx, userID, models.SessionListOpts{
		ListingOpts: models.ListingOpts{Limit: 1},
	})
	if err != nil || len(sessions) == 0 {
		return types.NewSessionNotFoundError()
	}

	if err := s.SessionRepository.DeleteByUserID(ctx, userID); err != nil {
		return types.NewInternalError("Failed to delete sessions")
	}

	return nil
}

// LogoutSession invalidates a specific session
func (s *SessionService) LogoutSession(ctx context.Context, userID, sessionID string) *types.GoAuthError {
	session, err := s.SessionRepository.FindByID(ctx, sessionID)
	if err != nil || session == nil {
		return types.NewSessionNotFoundError()
	}

	// Ensure the session belongs to the user
	if session.UserID != userID {
		return types.NewUnauthorizedError()
	}

	if err := s.SessionRepository.Delete(ctx, sessionID); err != nil {
		return types.NewInternalError("Failed to delete session")
	}

	return nil
}

