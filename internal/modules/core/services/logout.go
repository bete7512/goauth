package core_services

import (
	"context"

	"github.com/bete7512/goauth/pkg/types"
)

// Logout invalidates user session
func (s *CoreService) Logout(ctx context.Context, sessionToken string) *types.GoAuthError {
	session, err := s.SessionRepository.FindByToken(ctx, sessionToken)
	if err != nil || session == nil {
		return types.NewSessionNotFoundError()
	}

	if err := s.SessionRepository.Delete(ctx, session.ID); err != nil {
		return types.NewSessionNotFoundError()
	}

	// Emit after:logout event
	s.deps.Events.Emit(ctx, "after:logout", map[string]interface{}{
		"user_id": session.UserID,
	})

	return nil
}
