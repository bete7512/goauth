package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
)

// EnableTwoFactor enables two-factor authentication for a user
func (s *AuthService) EnableTwoFactor(ctx context.Context, userID string, req *dto.EnableTwoFactorRequest) (*dto.TwoFactorSetupResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Check if 2FA is already enabled
	if user.TwoFactorEnabled != nil && *user.TwoFactorEnabled {
		return nil, errors.New("two-factor authentication is already enabled")
	}

	// Generate TOTP secret
	secret, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Generate QR code URL (this would typically use a library like github.com/pquerna/otp)
	qrCode := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		s.Auth.Config.App.Domain,
		user.Email,
		secret,
		s.Auth.Config.App.Domain)

	// Generate backup codes
	backupCodes := make([]string, 8)
	for i := 0; i < 8; i++ {
		code, err := s.Auth.TokenManager.GenerateRandomToken(8)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		backupCodes[i] = code
	}

	// TODO: Save TOTP secret and backup codes to database
	// This would require implementing TOTP and backup code repositories

	return &dto.TwoFactorSetupResponse{
		Message:     "two-factor authentication setup initiated",
		QRCode:      qrCode,
		Secret:      secret,
		BackupCodes: backupCodes,
	}, nil
}

// VerifyTwoFactor verifies two-factor authentication code
func (s *AuthService) VerifyTwoFactor(ctx context.Context, userID string, req *dto.TwoFactorVerificationRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		return errors.New("two-factor authentication is not enabled")
	}

	// TODO: Implement TOTP verification
	// This would require implementing TOTP validation logic

	return errors.New("not implemented")
}

// DisableTwoFactor disables two-factor authentication for a user
func (s *AuthService) DisableTwoFactor(ctx context.Context, userID string, req *dto.DisableTwoFactorRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		return errors.New("two-factor authentication is not enabled")
	}

	// Verify password
	if err := s.Auth.TokenManager.ValidatePassword(user.Password, req.Password); err != nil {
		return errors.New("invalid password")
	}

	// Disable 2FA
	twoFactorEnabled := false
	user.TwoFactorEnabled = &twoFactorEnabled
	user.UpdatedAt = time.Now()

	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to disable two-factor authentication: %w", err)
	}

	// TODO: Clean up TOTP secrets and backup codes
	// This would require implementing cleanup logic

	return nil
}
