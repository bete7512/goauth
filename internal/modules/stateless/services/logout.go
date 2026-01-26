package services

import (
	"context"

	"github.com/bete7512/goauth/pkg/types"
)

// Logout invalidates all refresh tokens for a user by deleting their nonces
func (s *StatelessService) Logout(ctx context.Context, userID string) *types.GoAuthError {
	// Delete all refresh nonces for the user (effectively blacklisting all refresh tokens)
	if err := s.TokenRepository.DeleteByUserID(ctx, userID); err != nil {
		return types.NewInternalError("Failed to revoke tokens")
	}

	return nil
}

