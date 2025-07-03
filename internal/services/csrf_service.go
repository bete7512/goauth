package services

import (
	"context"
	"errors"
	"fmt"
)


// ValidateToken validates a CSRF token for a user
func (s *AuthService) ValidateToken(ctx context.Context, userID string, token string) error {
	if s.Auth.CSRFManager == nil {
		return errors.New("CSRF manager not configured")
	}

	valid, err := s.Auth.CSRFManager.ValidateToken(ctx, token, userID)
	if err != nil {
		return fmt.Errorf("failed to validate CSRF token: %w", err)
	}
	if !valid {
		return errors.New("invalid CSRF token")
	}

	return nil
}


func (s *AuthService) GetCSRFToken(ctx context.Context /*params*/) error {
	// TODO: Implement
	return nil
}
