package core

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type TokenRepository struct {
	db *gorm.DB
}

func (r *TokenRepository) Create(ctx context.Context, token *models.Token) error {
	if err := r.db.WithContext(ctx).Create(token).Error; err != nil {
		return fmt.Errorf("token_repository.Create: %w", err)
	}
	return nil
}

func (r *TokenRepository) FindByToken(ctx context.Context, token string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("token_repository.FindByToken: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("token_repository.FindByToken: %w", err)
	}
	return &t, nil
}

func (r *TokenRepository) FindByUserID(ctx context.Context, userID string) ([]*models.Token, error) {
	var tokens []*models.Token
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&tokens).Error; err != nil {
		return nil, fmt.Errorf("token_repository.FindByUserID: %w", err)
	}
	return tokens, nil
}

func (r *TokenRepository) FindByUserIDAndType(ctx context.Context, userID, tokenType string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND type = ?", userID, tokenType).
		Order("created_at DESC").
		First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("token_repository.FindByUserIDAndType: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("token_repository.FindByUserIDAndType: %w", err)
	}
	return &t, nil
}

func (r *TokenRepository) FindByCode(ctx context.Context, code, tokenType string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).
		Where("code = ? AND type = ? AND used = ? AND expires_at > ?", code, tokenType, false, time.Now()).
		First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("token_repository.FindByCode: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("token_repository.FindByCode: %w", err)
	}
	return &t, nil
}

func (r *TokenRepository) FindByEmailAndType(ctx context.Context, email, tokenType string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).
		Where("email = ? AND type = ? AND used = ? AND expires_at > ?", email, tokenType, false, time.Now()).
		Order("created_at DESC").
		First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("token_repository.FindByEmailAndType: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("token_repository.FindByEmailAndType: %w", err)
	}
	return &t, nil
}

func (r *TokenRepository) FindByPhoneAndType(ctx context.Context, phone, tokenType string) (*models.Token, error) {
	var t models.Token
	err := r.db.WithContext(ctx).
		Where("phone_number = ? AND type = ? AND used = ? AND expires_at > ?", phone, tokenType, false, time.Now()).
		Order("created_at DESC").
		First(&t).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("token_repository.FindByPhoneAndType: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("token_repository.FindByPhoneAndType: %w", err)
	}
	return &t, nil
}

func (r *TokenRepository) MarkAsUsed(ctx context.Context, id string) error {
	now := time.Now()
	if err := r.db.WithContext(ctx).
		Model(&models.Token{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": &now,
		}).Error; err != nil {
		return fmt.Errorf("token_repository.MarkAsUsed: %w", err)
	}
	return nil
}

func (r *TokenRepository) Delete(ctx context.Context, token string) error {
	if err := r.db.WithContext(ctx).Where("token = ?", token).Delete(&models.Token{}).Error; err != nil {
		return fmt.Errorf("token_repository.Delete: %w", err)
	}
	return nil
}

func (r *TokenRepository) DeleteByIDAndType(ctx context.Context, id string, tokenType string) error {
	if err := r.db.WithContext(ctx).
		Delete(&models.Token{}, "id = ? AND type = ?", id, tokenType).Error; err != nil {
		return fmt.Errorf("token_repository.DeleteByIDAndType: %w", err)
	}
	return nil
}

func (r *TokenRepository) DeleteByUserID(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.Token{}).Error; err != nil {
		return fmt.Errorf("token_repository.DeleteByUserID: %w", err)
	}
	return nil
}

func (r *TokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Token{})
	if result.Error != nil {
		return 0, fmt.Errorf("token_repository.DeleteExpired: %w", result.Error)
	}
	return result.RowsAffected, nil
}
