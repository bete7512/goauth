package auth_service

import (
	"context"

	"github.com/bete7512/goauth/pkg/types"
)

// ValidateToken validates a CSRF token for a user
func (s *AuthService) ValidateToken(ctx context.Context, userID string, token string) *types.GoAuthError {
	if s.config.CSRFManager == nil {
		msg := "CSRF manager not configured"
		return types.NewConfigurationError(&msg)
	}

	valid, err := s.config.CSRFManager.ValidateToken(ctx, token, userID)
	if err != nil {
		s.logger.Errorf("Failed to validate CSRF token: %v", err)
		return types.NewInternalError(err.Error())
	}
	if !valid {
		return types.NewInvalidCSRFError()
	}

	return nil
}

func (s *AuthService) GetCSRFToken(ctx context.Context, userID string) (string, *types.GoAuthError) {
	if s.config.CSRFManager == nil {
		msg := "CSRF manager not configured"
		return "", types.NewConfigurationError(&msg)
	}

	token, err := s.tokenMgr.GenerateRandomToken(32)
	if err != nil {
		s.logger.Errorf("Failed to generate CSRF token: %v", err)
		return "", types.NewInternalError(err.Error())
	}

	return token, nil
}
