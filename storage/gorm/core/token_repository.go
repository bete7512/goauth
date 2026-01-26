package core

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type TokenRepository struct {
	db *gorm.DB
}

func (r *TokenRepository) Create(ctx context.Context, token *models.Token) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *TokenRepository) FindByToken(ctx context.Context, token string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &t, err
}

func (r *TokenRepository) FindByUserID(ctx context.Context, userID string) ([]*models.Token, error) {
	var tokens []*models.Token
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&tokens).Error
	return tokens, err
}

func (r *TokenRepository) FindByUserIDAndType(ctx context.Context, userID, tokenType string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND type = ?", userID, tokenType).
		Order("created_at DESC").
		First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &t, err
}

func (r *TokenRepository) Delete(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&models.Token{}).Error
}

func (r *TokenRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Token{}).Error
}

func (r *TokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Token{})
	return result.RowsAffected, result.Error
}
