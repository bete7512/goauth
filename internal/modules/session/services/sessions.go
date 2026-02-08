package services

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// ListSessions returns all active sessions for a user
func (s *SessionService) ListSessions(ctx context.Context, userID string, currentSessionID string, opts models.SessionListOpts) ([]dto.SessionDTO, int64, *types.GoAuthError) {
	sessions, total, err := s.SessionRepository.FindByUserID(ctx, userID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("Failed to fetch sessions")
	}

	sessionDTOs := make([]dto.SessionDTO, len(sessions))
	for i, session := range sessions {
		sessionDTOs[i] = dto.SessionDTO{
			ID:        session.ID,
			UserAgent: session.UserAgent,
			IPAddress: session.IPAddress,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
			Current:   session.ID == currentSessionID,
		}
	}

	return sessionDTOs, total, nil
}

// GetSession returns a specific session by ID
func (s *SessionService) GetSession(ctx context.Context, userID, sessionID string) (*dto.SessionDTO, *types.GoAuthError) {
	session, err := s.SessionRepository.FindByID(ctx, sessionID)
	if err != nil || session == nil {
		return nil, types.NewSessionNotFoundError()
	}

	// Ensure the session belongs to the user
	if session.UserID != userID {
		return nil, types.NewUnauthorizedError()
	}

	return &dto.SessionDTO{
		ID:        session.ID,
		UserAgent: session.UserAgent,
		IPAddress: session.IPAddress,
		CreatedAt: session.CreatedAt,
		ExpiresAt: session.ExpiresAt,
	}, nil
}

// DeleteSession deletes a specific session by ID
func (s *SessionService) DeleteSession(ctx context.Context, userID, sessionID string) *types.GoAuthError {
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

// DeleteAllSessions deletes all sessions for a user
func (s *SessionService) DeleteAllSessions(ctx context.Context, userID string) *types.GoAuthError {
	if err := s.SessionRepository.DeleteByUserID(ctx, userID); err != nil {
		return types.NewInternalError("Failed to delete sessions")
	}

	return nil
}

