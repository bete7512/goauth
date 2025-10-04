package core

import (
	"context"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/models"
	"gorm.io/gorm"
)

type TokenRepository struct {
	db *gorm.DB
}

var _ models.TokenRepository = (*TokenRepository)(nil)

func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) Create(ctx context.Context, token *models.Token) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *TokenRepository) Delete(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&models.Token{}).Error
}

func (r *TokenRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Token{}).Error
}
func (r *TokenRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Token{}).Error
}

func (r *TokenRepository) FindByUserID(ctx context.Context, userID string) ([]*models.Token, error) {
	var tokens []*models.Token
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&tokens).Error
	return tokens, err
}

func (r *TokenRepository) FindByToken(ctx context.Context, token string) (*models.Token, error) {
	var t *models.Token
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&t).Error
	return t, err
}

func (r *TokenRepository) Update(ctx context.Context, token *models.Token) error {
	return r.db.WithContext(ctx).Save(token).Error
}

func (r *TokenRepository) MarkAsUsed(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Model(&models.Token{}).Where("id = ?", id).Update("used", true).Error
}
