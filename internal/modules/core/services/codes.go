package core_services

import (
	"context"
	"github.com/bete7512/goauth/internal/security"
	"net/http"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

const defaultMaxCodeAttempts = 5

// maxCodeAttempts returns how many wrong submissions a short code tolerates.
func (s *coreService) maxCodeAttempts() int {
	if s.Config != nil && s.Config.MaxCodeAttempts > 0 {
		return s.Config.MaxCodeAttempts
	}
	return defaultMaxCodeAttempts
}

// checkCode compares a submitted short code with the token issued to the
// account it belongs to. Callers must look the token up by its account (phone
// or email), never by the submitted code, so that wrong guesses are counted
// against the right token. Once the attempt budget is spent the token is
// consumed and the correct code is rejected too; the user requests a new one.
func (s *coreService) checkCode(ctx context.Context, token *models.Token, submitted string) *types.GoAuthError {
	max := s.maxCodeAttempts()
	if token.Attempts >= max {
		return tooManyCodeAttempts()
	}
	if security.CodeMatches(s.codeKey(), token.ID, token.Code, submitted) {
		return nil
	}
	attempts, err := s.TokenRepository.IncrementAttempts(ctx, token.ID)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Errorf("core: failed to count code attempt: %v", err)
		}
		return invalidCode()
	}
	if attempts >= max {
		if err := s.TokenRepository.MarkAsUsed(ctx, token.ID); err != nil && s.Logger != nil {
			s.Logger.Errorf("core: failed to consume exhausted code: %v", err)
		}
		return tooManyCodeAttempts()
	}
	return invalidCode()
}

func invalidCode() *types.GoAuthError {
	return types.NewGoAuthError(types.ErrInvalidToken, "invalid code", http.StatusBadRequest)
}

// codeKey is the key for short-code digests, derived from the JWT secret.
func (s *coreService) codeKey() []byte {
	if s.Deps.Config == nil {
		return security.CodeKey(types.SecurityConfig{})
	}
	return security.CodeKey(s.Deps.Config.Security)
}

func tooManyCodeAttempts() *types.GoAuthError {
	return types.NewGoAuthError(types.ErrInvalidToken, "too many attempts, request a new code", http.StatusTooManyRequests)
}
