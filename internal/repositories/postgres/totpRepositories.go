package postgres

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type TotpSecretRepository struct {
	Db *gorm.DB
}

func NewTotpSecretRepository(db *gorm.DB) *TotpSecretRepository {
	return &TotpSecretRepository{Db: db}
}

func (r *TotpSecretRepository) GetTOTPSecretByUserID(ctx context.Context, userID string) (*models.TotpSecret, error) {
	var totpSecret models.TotpSecret
	if err := r.Db.WithContext(ctx).Where("user_id = ?", userID).First(&totpSecret).Error; err != nil {
		return nil, err
	}
	return &totpSecret, nil
}

func (r *TotpSecretRepository) CreateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	return r.Db.WithContext(ctx).Create(secret).Error
}

func (r *TotpSecretRepository) UpdateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	return r.Db.WithContext(ctx).Save(secret).Error
}

func (r *TotpSecretRepository) DeleteTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	return r.Db.WithContext(ctx).Delete(secret).Error
}
