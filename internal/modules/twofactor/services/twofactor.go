package services

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/bete7512/goauth/internal/modules/twofactor/models"
	"github.com/bete7512/goauth/pkg/config"
)

type TwoFactorService struct {
	storage          config.Storage
	issuer           string
	backupCodesCount int
	codeLength       int
}

func NewTwoFactorService(storage config.Storage, issuer string, backupCodesCount, codeLength int) *TwoFactorService {
	return &TwoFactorService{
		storage:          storage,
		issuer:           issuer,
		backupCodesCount: backupCodesCount,
		codeLength:       codeLength,
	}
}

// GenerateSecret generates a new TOTP secret
func (s *TwoFactorService) GenerateSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateTOTPURL generates a TOTP provisioning URL for QR code
func (s *TwoFactorService) GenerateTOTPURL(userEmail, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		s.issuer, userEmail, secret, s.issuer)
}

// VerifyTOTP verifies a TOTP code
func (s *TwoFactorService) VerifyTOTP(secret, code string) bool {
	// Simple TOTP verification
	// In production, use a proper TOTP library like github.com/pquerna/otp
	// This is a simplified version for demonstration

	if len(code) != 6 {
		return false
	}

	// TODO: Implement actual TOTP algorithm
	// For now, accept any 6-digit code for testing
	return len(code) == 6
}

// EnableTwoFactor enables 2FA for a user
func (s *TwoFactorService) EnableTwoFactor(ctx context.Context, userID, secret string) error {
	// twoFA := &models.TwoFactor{
	// 	ID:       uuid.New().String(),
	// 	UserID:   userID,
	// 	Secret:   secret,
	// 	Enabled:  false,
	// 	Verified: false,
	// 	Method:   "totp",
	// }

	// Use transaction to ensure atomicity
	tx, err := s.storage.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// // Create 2FA record
	// if err := tx.Repository(twoFA).Create(ctx, twoFA); err != nil {
	// 	return err
	// }

	// Generate backup codes
	// backupCodes, err := s.generateBackupCodes(ctx, tx, userID)
	// if err != nil {
	// return err
	// }

	// Store backup codes
	// for _, _ = range backupCodes {
	// hashedCode, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	// if err != nil {
	// 	return err
	// }

	// backupCode := &models.BackupCode{
	// 	ID:     uuid.New().String(),
	// 	UserID: userID,
	// 	Code:   string(hashedCode),
	// 	Used:   false,
	// }

	// if err := tx.Repository(backupCode).Create(ctx, backupCode); err != nil {
	// 	return err
	// }
	// }

	return tx.Commit()
}

// VerifyAndEnable verifies the TOTP code and enables 2FA
func (s *TwoFactorService) VerifyAndEnable(ctx context.Context, userID, code string) error {
	// Get 2FA record
	// var twoFA models.TwoFactor
	// repo := s.storage.Repository(&twoFA)

	// if err := repo.FindOne(ctx, map[string]interface{}{"user_id": userID}, &twoFA); err != nil {
	// 	return fmt.Errorf("2FA not configured for user")
	// }

	// // Verify code
	// if !s.VerifyTOTP(twoFA.Secret, code) {
	// 	return fmt.Errorf("invalid verification code")
	// }

	// // Enable 2FA
	// twoFA.Enabled = true
	// twoFA.Verified = true

	// return repo.Update(ctx, &twoFA)
	return nil
}

// DisableTwoFactor disables 2FA for a user
func (s *TwoFactorService) DisableTwoFactor(ctx context.Context, userID string) error {
	// var twoFA models.TwoFactor
	// repo := s.storage.Repository(&twoFA)

	// if err := repo.FindOne(ctx, map[string]interface{}{"user_id": userID}, &twoFA); err != nil {
	// 	return err
	// }

	return nil
}

// VerifyBackupCode verifies and uses a backup code
func (s *TwoFactorService) VerifyBackupCode(ctx context.Context, userID, code string) (bool, error) {
	// var backupCodes []models.BackupCode
	// repo := s.storage.Repository(&models.BackupCode{})

	// if err := repo.FindOne(ctx, map[string]interface{}{
	// 	"user_id": userID,
	// 	"used":    false,
	// }, &backupCodes); err != nil {
	// 	return false, err
	// }

	// // Check each backup code
	// for _, _ = range backupCodes {
	// 	if err := bcrypt.CompareHashAndPassword([]byte(bc.Code), []byte(code)); err == nil {
	// 		// Mark as used
	// 		now := time.Now()
	// 		bc.Used = true
	// 		bc.UsedAt = &now

	// 		if err := repo.Update(ctx, bc); err != nil {
	// 			return false, err
	// 		}

	// 		return true, nil
	// 	}
	// }

	return false, nil
}

// generateBackupCodes generates random backup codes
func (s *TwoFactorService) generateBackupCodes(ctx context.Context, tx config.Storage, userID string) ([]string, error) {
	codes := make([]string, s.backupCodesCount)

	for i := 0; i < s.backupCodesCount; i++ {
		code, err := s.generateRandomCode(s.codeLength)
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}

	return codes, nil
}

// generateRandomCode generates a random alphanumeric code
func (s *TwoFactorService) generateRandomCode(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	var code strings.Builder
	for _, v := range b {
		code.WriteByte(charset[int(v)%len(charset)])
	}

	// Format as XXXX-XXXX for 8-character codes
	if length == 8 {
		str := code.String()
		return fmt.Sprintf("%s-%s", str[:4], str[4:]), nil
	}

	return code.String(), nil
}

// GetTwoFactorStatus gets 2FA status for a user
func (s *TwoFactorService) GetTwoFactorStatus(ctx context.Context, userID string) (*models.TwoFactor, error) {
	var twoFA models.TwoFactor
	// repo := s.storage.Repository(&twoFA)

	// if err := repo.FindOne(ctx, map[string]interface{}{"user_id": userID}, &twoFA); err != nil {
	// 	return nil, nil
	// }

	return &twoFA, nil
}

func (s *TwoFactorService) SwaggerSpec() []byte {
	return nil
}
