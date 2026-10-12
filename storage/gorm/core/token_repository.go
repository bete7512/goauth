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
	token.CreatedAt = token.CreatedAt.UTC()
	token.ExpiresAt = token.ExpiresAt.UTC()
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
		Where("code = ? AND type = ? AND used = ? AND expires_at > ?", code, tokenType, false, time.Now().UTC()).
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
		Where("email = ? AND type = ? AND used = ? AND expires_at > ?", email, tokenType, false, time.Now().UTC()).
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
		Where("phone_number = ? AND type = ? AND used = ? AND expires_at > ?", phone, tokenType, false, time.Now().UTC()).
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

func (r *TokenRepository) IncrementAttempts(ctx context.Context, id string) (int, error) {
	if err := r.db.WithContext(ctx).
		Model(&models.Token{}).
		Where("id = ?", id).
		UpdateColumn("attempts", gorm.Expr("attempts + ?", 1)).Error; err != nil {
		return 0, fmt.Errorf("token_repository.IncrementAttempts: %w", err)
	}
	var updated models.Token
	if err := r.db.WithContext(ctx).Select("attempts").Where("id = ?", id).First(&updated).Error; err != nil {
		return 0, fmt.Errorf("token_repository.IncrementAttempts: %w", err)
	}
	return updated.Attempts, nil
}

func (r *TokenRepository) MarkAsUsed(ctx context.Context, id string) error {
	now := time.Now().UTC()
	result := r.db.WithContext(ctx).
		Model(&models.Token{}).
		Where("id = ? AND used = ? AND expires_at > ?", id, false, now).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": &now,
		})
	if result.Error != nil {
		return fmt.Errorf("token_repository.MarkAsUsed: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return models.ErrConflict
	}
	return nil
}

func (r *TokenRepository) Rotate(ctx context.Context, expected *models.Token, replacement *models.Token) error {
	if expected.UserID != replacement.UserID || expected.Type != replacement.Type {
		return models.ErrConflict
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		result := tx.Model(&models.Token{}).Where("id = ? AND token = ? AND user_id = ? AND type = ? AND used = ? AND expires_at > ?", expected.ID, expected.Token, expected.UserID, expected.Type, false, now).Updates(map[string]interface{}{"used": true, "used_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return models.ErrConflict
		}
		replacement.CreatedAt = replacement.CreatedAt.UTC()
		replacement.ExpiresAt = replacement.ExpiresAt.UTC()
		return tx.Create(replacement).Error
	})
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
	result := r.db.WithContext(ctx).Where("expires_at < ?", time.Now().UTC()).Delete(&models.Token{})
	if result.Error != nil {
		return 0, fmt.Errorf("token_repository.DeleteExpired: %w", result.Error)
	}
	return result.RowsAffected, nil
}
