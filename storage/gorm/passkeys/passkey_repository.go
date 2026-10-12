package passkeys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type PasskeyRepository struct {
	db *gorm.DB
}

var _ models.PasskeyRepository = (*PasskeyRepository)(nil)

func NewPasskeyRepository(db *gorm.DB) *PasskeyRepository {
	return &PasskeyRepository{db: db}
}

func (r *PasskeyRepository) Create(ctx context.Context, cred *models.PasskeyCredential) error {
	if err := r.db.WithContext(ctx).Create(cred).Error; err != nil {
		return fmt.Errorf("passkey_repository.Create: %w", err)
	}
	return nil
}

func (r *PasskeyRepository) FindByID(ctx context.Context, id string) (*models.PasskeyCredential, error) {
	var c models.PasskeyCredential
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("passkey_repository.FindByID: %w", err)
	}
	return &c, nil
}

func (r *PasskeyRepository) FindByCredentialID(ctx context.Context, credentialID []byte) (*models.PasskeyCredential, error) {
	var c models.PasskeyCredential
	err := r.db.WithContext(ctx).Where("credential_id = ?", credentialID).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("passkey_repository.FindByCredentialID: %w", err)
	}
	return &c, nil
}

func (r *PasskeyRepository) ListByUserID(ctx context.Context, userID string) ([]*models.PasskeyCredential, error) {
	var out []*models.PasskeyCredential
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("passkey_repository.ListByUserID: %w", err)
	}
	return out, nil
}

func (r *PasskeyRepository) UpdateSignCount(ctx context.Context, id string, signCount uint32) error {
	result := r.db.WithContext(ctx).
		Model(&models.PasskeyCredential{}).
		Where("id = ? AND (sign_count < ? OR (sign_count = 0 AND ? = 0))", id, signCount, signCount).
		Updates(map[string]interface{}{"sign_count": signCount, "last_used_at": time.Now().UTC()})
	if result.Error != nil {
		return fmt.Errorf("passkey_repository.UpdateSignCount: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return models.ErrConflict
	}
	return nil
}

func (r *PasskeyRepository) UpdateLastUsed(ctx context.Context, id string, at time.Time) error {
	if err := r.db.WithContext(ctx).
		Model(&models.PasskeyCredential{}).
		Where("id = ?", id).
		Update("last_used_at", at).Error; err != nil {
		return fmt.Errorf("passkey_repository.UpdateLastUsed: %w", err)
	}
	return nil
}

func (r *PasskeyRepository) UpdateName(ctx context.Context, id, name string) error {
	if err := r.db.WithContext(ctx).
		Model(&models.PasskeyCredential{}).
		Where("id = ?", id).
		Update("name", name).Error; err != nil {
		return fmt.Errorf("passkey_repository.UpdateName: %w", err)
	}
	return nil
}

func (r *PasskeyRepository) Delete(ctx context.Context, id string) error {
	if err := r.db.WithContext(ctx).Delete(&models.PasskeyCredential{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("passkey_repository.Delete: %w", err)
	}
	return nil
}

func (r *PasskeyRepository) DeleteByUserID(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.PasskeyCredential{}).Error; err != nil {
		return fmt.Errorf("passkey_repository.DeleteByUserID: %w", err)
	}
	return nil
}
