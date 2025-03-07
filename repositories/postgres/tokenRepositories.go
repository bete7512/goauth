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
	return t.db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND used = ? AND expires_at > ?",
			userID, models.RefreshToken, false, time.Now()).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": time.Now(),
		}).Error
}

// InvalidateEmailVerificationToken invalidates a specific email verification token
func (t *TokenRepository) InvalidateEmailVerificationToken(userID string, token string) error {
	return t.db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
			userID, models.EmailVerificationToken, token, false, time.Now()).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": time.Now(),
		}).Error
}

// InvalidatePasswordResetToken invalidates a password reset token
func (t *TokenRepository) InvalidatePasswordResetToken(token string) error {
	return t.db.Model(&models.Token{}).
		Where("token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
			models.PasswordResetToken, token, false, time.Now()).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": time.Now(),
		}).Error
}

// InvalidateRefreshToken invalidates a specific refresh token
func (t *TokenRepository) InvalidateRefreshToken(userID string, token string) error {
	return t.db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
			userID, models.RefreshToken, token, false, time.Now()).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": time.Now(),
		}).Error
}

// InvalidateTwoFactorCode invalidates a two-factor authentication code
func (t *TokenRepository) InvalidateTwoFactorCode(userID string, code string) error {
	return t.db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
			userID, models.TwoFactorCode, code, false, time.Now()).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": time.Now(),
		}).Error
}

// SaveEmailVerificationToken saves a new email verification token
func (t *TokenRepository) SaveEmailVerificationToken(userID string, token string, expiry time.Duration) error {
	newToken := models.Token{
		UserID:     userID,
		TokenType:  models.EmailVerificationToken,
		TokenValue: token,
		ExpiresAt:  time.Now().Add(expiry),
		Used:       false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	return t.db.Create(&newToken).Error
}

// SavePasswordResetToken saves a new password reset token
func (t *TokenRepository) SavePasswordResetToken(userID string, token string, expiry time.Duration) error {
	newToken := models.Token{
		UserID:     userID,
		TokenType:  models.PasswordResetToken,
		TokenValue: token,
		ExpiresAt:  time.Now().Add(expiry),
		Used:       false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	return t.db.Create(&newToken).Error
}

// SaveRefreshToken saves a new refresh token
func (t *TokenRepository) SaveRefreshToken(userID string, token string, expiry time.Duration) error {
	newToken := models.Token{
		UserID:     userID,
		TokenType:  models.RefreshToken,
		TokenValue: token,
		ExpiresAt:  time.Now().Add(expiry),
		Used:       false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	return t.db.Create(&newToken).Error
}

// SaveTwoFactorCode saves a new two-factor authentication code
func (t *TokenRepository) SaveTwoFactorCode(userID string, code string, expiry time.Duration) error {
	newToken := models.Token{
		UserID:     userID,
		TokenType:  models.TwoFactorCode,
		TokenValue: code,
		ExpiresAt:  time.Now().Add(expiry),
		Used:       false,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
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
