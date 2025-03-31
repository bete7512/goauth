package postgres

import (
	"time"

	"github.com/bete7512/goauth/models"
	"gorm.io/gorm"
)

type TokenRepository struct {
	db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// InvalidateAllRefreshTokens invalidates all refresh tokens for a user
func (t *TokenRepository) InvalidateAllRefreshTokens(userID string) error {
	now := time.Now()
	return t.db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND used = ? AND expires_at > ?",
			userID, models.RefreshToken, false, now).
		Updates(models.Token{
			Used:      true,
			UpdatedAt: now,
		}).Error
}

// InvalidateEmailVerificationToken invalidates a specific email verification token
func (t *TokenRepository) InvalidateEmailVerificationToken(userID string, token string) error {
	now := time.Now()
	return t.db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
			userID, models.EmailVerificationToken, token, false, now).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": now,
		}).Error
}

// InvalidatePasswordResetToken invalidates a password reset token
func (t *TokenRepository) InvalidatePasswordResetToken(token string) error {
	now := time.Now()
	return t.db.Model(&models.Token{}).
		Where("token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
			models.PasswordResetToken, token, false, now).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": now,
		}).Error
}

// InvalidateRefreshToken invalidates a specific refresh token
func (t *TokenRepository) InvalidateRefreshToken(userID string, token string) error {
	now := time.Now()
	return t.db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
			userID, models.RefreshToken, token, false, now).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": now,
		}).Error
}

// InvalidateTwoFactorCode invalidates a two-factor authentication code
func (t *TokenRepository) InvalidateTwoFactorCode(userID string, code string) error {
	now := time.Now()
	return t.db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
			userID, models.TwoFactorCode, code, false, now).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": now,
		}).Error
}

// SaveEmailVerificationToken saves a new email verification token
func (t *TokenRepository) SaveEmailVerificationToken(userID string, token string, expiry time.Duration) error {
	return t.saveToken(userID, string(models.EmailVerificationToken), token, expiry)
}

// SavePasswordResetToken saves a new password reset token
func (t *TokenRepository) SavePasswordResetToken(userID string, token string, expiry time.Duration) error {
	return t.saveToken(userID, string(models.PasswordResetToken), token, expiry)
}

// SaveRefreshToken saves a new refresh token
func (t *TokenRepository) SaveRefreshToken(userID string, token string, expiry time.Duration) error {
	return t.saveToken(userID, string(models.RefreshToken), token, expiry)
}

// SaveTwoFactorCode saves a new two-factor authentication code
func (t *TokenRepository) SaveTwoFactorCode(userID string, code string, expiry time.Duration) error {
	return t.saveToken(userID, string(models.TwoFactorCode), code, expiry)
}

// SaveMagicLinkToken saves a new magic link token
func (t *TokenRepository) SaveMagicLinkToken(userID string, token string, expiry time.Duration) error {
	return t.saveToken(userID, string(models.MakicLinkToken), token, expiry)
}

// saveToken is a helper function to save tokens of any type
func (t *TokenRepository) saveToken(userID string, tokenType string, tokenValue string, expiry time.Duration) error {
	now := time.Now()
	newToken := models.Token{
		UserID:     userID,
		TokenType:  models.TokenType(tokenType),
		TokenValue: tokenValue,
		ExpiresAt:  now.Add(expiry),
		Used:       false,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	return t.db.Create(&newToken).Error
}

// ValidateEmailVerificationToken validates an email verification token
func (t *TokenRepository) ValidateEmailVerificationToken(userID string, token string) (bool, error) {
	var tokenRecord models.Token

	result := t.db.Where(
		"user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
		userID, models.EmailVerificationToken, token, false, time.Now(),
	).First(&tokenRecord)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, result.Error
	}

	return true, nil
}

// ValidatePasswordResetToken validates a password reset token and returns the associated user ID
func (t *TokenRepository) ValidatePasswordResetToken(token string) (bool, string, error) {
	var tokenRecord models.Token

	result := t.db.Where(
		"token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
		models.PasswordResetToken, token, false, time.Now(),
	).First(&tokenRecord)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false, "", nil
		}
		return false, "", result.Error
	}

	return true, tokenRecord.UserID, nil
}

// ValidateRefreshToken validates a refresh token
func (t *TokenRepository) ValidateRefreshToken(userID string, token string) (bool, error) {
	var tokenRecord models.Token

	result := t.db.Where(
		"user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
		userID, models.RefreshToken, token, false, time.Now(),
	).First(&tokenRecord)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, result.Error
	}

	return true, nil
}

// ValidateTwoFactorCode validates a two-factor authentication code
func (t *TokenRepository) ValidateTwoFactorCode(userID string, code string) (bool, error) {
	var tokenRecord models.Token

	result := t.db.Where(
		"user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
		userID, models.TwoFactorCode, code, false, time.Now(),
	).First(&tokenRecord)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, result.Error
	}

	return true, nil
}

// ValidateMagicLinkToken validates a magic link token
func (t *TokenRepository) ValidateMagicLinkToken(token string) (bool, string, error) {
	var tokenRecord models.Token
	result := t.db.Where(
		"token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
		models.MakicLinkToken, token, false, time.Now(),
	).First(&tokenRecord)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false, "", nil
		}
		return false, "", result.Error
	}
	return true, tokenRecord.UserID, nil
}
