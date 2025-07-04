package sqlserver

import (
	"context"
	"errors"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type TokenRepository struct {
	Db *gorm.DB
}

// GetTokenByUserID implements interfaces.TokenRepository.

func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{Db: db}
}

// SaveToken saves a token of any type
func (t *TokenRepository) SaveToken(ctx context.Context, userID, token string, tokenType models.TokenType, expiry time.Duration) error {
	now := time.Now()
	used := false
	newToken := models.Token{
		UserID:     userID,
		TokenType:  tokenType,
		TokenValue: token,
		ExpiresAt:  now.Add(expiry),
		Used:       &used,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	return t.Db.Create(&newToken).Error
}

// GetActiveTokenByUserIdAndType implements interfaces.TokenRepository.
func (t *TokenRepository) GetActiveTokenByUserIdAndType(ctx context.Context, userID string, tokenType models.TokenType) (*models.Token, error) {
	var token models.Token
	if err := t.Db.Where("user_id = ? AND token_type = ? AND used = ? AND expires_at > ?", userID, tokenType, false, time.Now()).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

// RevokeToken implements interfaces.TokenRepository.
func (t *TokenRepository) RevokeToken(ctx context.Context, tokenId string) error {
	return t.Db.Model(&models.Token{}).Where("id = ?", tokenId).Update("used", true).Error
}

// RevokeAllTokens implements interfaces.TokenRepository.
func (t *TokenRepository) RevokeAllTokens(ctx context.Context, userID string, tokenType models.TokenType) error {
	return t.Db.Model(&models.Token{}).Where("user_id = ? AND token_type = ?", userID, tokenType).Update("used", true).Error
}

// CleanExpiredTokens implements interfaces.TokenRepository.
func (t *TokenRepository) CleanExpiredTokens(ctx context.Context, tokenType models.TokenType) error {
	return t.Db.Model(&models.Token{}).Where("token_type = ? AND expires_at < ?", tokenType, time.Now()).Update("used", true).Error
}
