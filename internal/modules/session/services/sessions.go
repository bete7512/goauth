package services

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// ListSessions returns all active sessions for a user
func (s *sessionService) ListSessions(ctx context.Context, userID string, currentSessionID string, opts models.SessionListOpts) ([]dto.SessionDTO, int64, *types.GoAuthError) {
	sessions, total, err := s.sessionRepository.FindByUserID(ctx, userID, opts)
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
func (s *sessionService) GetSession(ctx context.Context, userID, sessionID string) (*dto.SessionDTO, *types.GoAuthError) {
	session, err := s.sessionRepository.FindByID(ctx, sessionID)
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
func (s *sessionService) DeleteSession(ctx context.Context, userID, sessionID string) *types.GoAuthError {
	session, err := s.sessionRepository.FindByID(ctx, sessionID)
	if err != nil || session == nil {
		return types.NewSessionNotFoundError()
	}

	// Ensure the session belongs to the user
	if session.UserID != userID {
		return types.NewUnauthorizedError()
	}

	if err := s.sessionRepository.Delete(ctx, sessionID); err != nil {
		return types.NewInternalError("Failed to delete session")
	}

	return nil
}

// DeleteAllSessions deletes all sessions for a user
func (s *sessionService) DeleteAllSessions(ctx context.Context, userID string) *types.GoAuthError {
	if err := s.sessionRepository.DeleteByUserID(ctx, userID); err != nil {
		return types.NewInternalError("Failed to delete sessions")
	}

	return nil
}

// FindSessionByToken finds a session by its refresh token
func (s *sessionService) FindSessionByToken(ctx context.Context, token string) (*models.Session, *types.GoAuthError) {
	session, err := s.sessionRepository.FindByToken(ctx, token)
	if err != nil || session == nil {
		return nil, types.NewSessionNotFoundError()
	}
	return session, nil
}
