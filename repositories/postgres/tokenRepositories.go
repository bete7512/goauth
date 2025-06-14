package postgres

import (
	"time"

	"github.com/bete7512/goauth/models"
	"gorm.io/gorm"
)

type TokenRepository struct {
	Db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{Db: db}
}

// SaveToken saves a token of any type
func (t *TokenRepository) SaveToken(userID, token string, tokenType models.TokenType, expiry time.Duration) error {
	now := time.Now()
	newToken := models.Token{
		UserID:     userID,
		TokenType:  tokenType,
		TokenValue: token,
		ExpiresAt:  now.Add(expiry),
		Used:       false,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	return t.Db.Create(&newToken).Error
}

// ValidateToken validates a token of any type
func (t *TokenRepository) ValidateToken(token string, tokenType models.TokenType) (bool, *string, error) {
	var tokenRecord models.Token

	result := t.Db.Where(
		"token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
		tokenType, token, false, time.Now(),
	).First(&tokenRecord)
	
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false, nil, nil
		}
		return false, nil, result.Error
	}

	return true, &tokenRecord.UserID, nil
}

// ValidateTokenWithUserID validates a token with a specific user ID
func (t *TokenRepository) ValidateTokenWithUserID(userID, token string, tokenType models.TokenType) (bool, error) {
	var tokenRecord models.Token

	result := t.Db.Where(
		"user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
		userID, tokenType, token, false, time.Now(),
	).First(&tokenRecord)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, result.Error
	}

	return true, nil
}

// InvalidateToken invalidates a specific token
func (t *TokenRepository) InvalidateToken(userID, token string, tokenType models.TokenType) error {
	now := time.Now()
	return t.Db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND token_value = ? AND used = ? AND expires_at > ?",
			userID, tokenType, token, false, now).
		Updates(map[string]interface{}{
			"used":       true,
			"updated_at": now,
		}).Error
}

// InvalidateAllTokens invalidates all tokens of a specific type for a user
func (t *TokenRepository) InvalidateAllTokens(userID string, tokenType models.TokenType) error {
	now := time.Now()
	return t.Db.Model(&models.Token{}).
		Where("user_id = ? AND token_type = ? AND used = ? AND expires_at > ?",
			userID, tokenType, false, now).
		Updates(models.Token{
			Used:      true,
			UpdatedAt: now,
		}).Error
}
