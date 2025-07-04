package services

import (
	"context"
	"errors"
)

// ValidateToken validates a CSRF token for a user
func (s *AuthService) ValidateToken(ctx context.Context, userID string, token string) error {
	if s.Auth.CSRFManager == nil {
		return errors.New("CSRF manager not configured")
	}

	valid, err := s.Auth.CSRFManager.ValidateToken(ctx, token, userID)
	if err != nil {
		s.Auth.Logger.Errorf("Failed to validate CSRF token: %v", err)
		return errors.New("failed to validate CSRF token")
	}
	if !valid {
		return errors.New("invalid CSRF token")
	}

	return nil
}

func (s *AuthService) GetCSRFToken(ctx context.Context, userID string) (token string, err error) {
	if s.Auth.CSRFManager == nil {
		return "", errors.New("CSRF manager not configured")
	}

	token, err = s.Auth.CSRFManager.GenerateToken(ctx, userID)
	if err != nil {
		s.Auth.Logger.Errorf("Failed to generate CSRF token: %v", err)
		return "", errors.New("failed to generate CSRF token")
	}

	return token, nil
}
