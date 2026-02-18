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

func (r *TokenRepository) FindByCode(ctx context.Context, code, tokenType string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).
		Where("code = ? AND type = ? AND used = ? AND expires_at > ?", code, tokenType, false, time.Now()).
		First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &t, err
}

func (r *TokenRepository) FindByEmailAndType(ctx context.Context, email, tokenType string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).
		Where("email = ? AND type = ? AND used = ? AND expires_at > ?", email, tokenType, false, time.Now()).
		Order("created_at DESC").
		First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &t, err
}

func (r *TokenRepository) FindByPhoneAndType(ctx context.Context, phone, tokenType string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).
		Where("phone_number = ? AND type = ? AND used = ? AND expires_at > ?", phone, tokenType, false, time.Now()).
		Order("created_at DESC").
		First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &t, err
}

func (r *TokenRepository) MarkAsUsed(ctx context.Context, id string) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&models.Token{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": &now,
		}).Error
}

func (r *TokenRepository) Delete(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&models.Token{}).Error
}

func (r *TokenRepository) DeleteByIDAndType(ctx context.Context, id string, tokenType string) error {
	return r.db.WithContext(ctx).
		Delete(&models.Token{}, "id = ? AND type = ?", id, tokenType).Error
}

func (r *TokenRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Token{}).Error
}

func (r *TokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Token{})
	return result.RowsAffected, result.Error
}
