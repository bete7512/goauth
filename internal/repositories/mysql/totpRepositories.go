package mysql

import (
	"context"
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type TotpSecretRepository struct {
	db *gorm.DB
}

func NewTotpSecretRepository(db *gorm.DB) interfaces.TotpSecretRepository {
	return &TotpSecretRepository{db: db}
}

func (t *TotpSecretRepository) GetTOTPSecretByUserID(ctx context.Context, userID string) (*models.TotpSecret, error) {
	var secret models.TotpSecret
	if err := t.db.Where("user_id = ?", userID).First(&secret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get TOTP secret: %w", err)
	}
	return &secret, nil
}

func (t *TotpSecretRepository) CreateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	if err := t.db.Create(secret).Error; err != nil {
		return fmt.Errorf("failed to create TOTP secret: %w", err)
	}
	return nil
}

func (t *TotpSecretRepository) UpdateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	if err := t.db.Model(&models.TotpSecret{}).Where("user_id = ?", secret.UserID).Updates(secret).Error; err != nil {
		return fmt.Errorf("failed to update TOTP secret: %w", err)
	}
	return nil
}

func (t *TotpSecretRepository) DeleteTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	if err := t.db.Delete(secret).Error; err != nil {
		return fmt.Errorf("failed to delete TOTP secret: %w", err)
	}
	return nil
}
