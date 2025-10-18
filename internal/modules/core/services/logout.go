package core_services

import (
	"context"

	"github.com/bete7512/goauth/pkg/types"
)

// Logout invalidates user session
func (s *CoreService) Logout(ctx context.Context, userID string) *types.GoAuthError {
	sessions, err := s.SessionRepository.FindByUserID(ctx, userID)
	if err != nil || len(sessions) == 0 {
		return types.NewSessionNotFoundError()
	}

	if err := s.SessionRepository.DeleteByUserID(ctx, userID); err != nil {
		return types.NewSessionNotFoundError()
	}
	

	return nil
}
