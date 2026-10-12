package services

import (
	"context"
	"github.com/bete7512/goauth/pkg/models"

	"github.com/bete7512/goauth/pkg/types"
)

// Logout invalidates all refresh tokens for a user by deleting their nonces
func (s *StatelessService) Logout(ctx context.Context, userID string) *types.GoAuthError {
	if mutator, ok := s.UserRepository.(models.UserCredentialMutator); ok {
		if err := mutator.RevokeTokens(ctx, userID); err != nil {
			return types.NewInternalError("failed to revoke access credentials").Wrap(err)
		}
	} else {
		user, err := s.UserRepository.FindByID(ctx, userID)
		if err != nil {
			return types.NewInternalError("failed to find user").Wrap(err)
		}
		user.TokenVersion++
		if err := s.UserRepository.Update(ctx, user); err != nil {
			return types.NewInternalError("failed to revoke access credentials").Wrap(err)
		}
	}

	// Delete all refresh nonces for the user (effectively blacklisting all refresh tokens)
	if err := s.TokenRepository.DeleteByUserID(ctx, userID); err != nil {
		return types.NewInternalError("failed to revoke tokens").Wrap(err)
	}

	return nil
}
