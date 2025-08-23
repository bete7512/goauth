package postgres

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type BackupCodeRepository struct {
	Db *gorm.DB
}

func NewBackupCodeRepository(db *gorm.DB) *BackupCodeRepository {
	return &BackupCodeRepository{Db: db}
}

func (r *BackupCodeRepository) GetBackupCodeByUserID(ctx context.Context, userID string) (*models.BackupCode, error) {
	var backupCode models.BackupCode
	if err := r.Db.WithContext(ctx).Where("user_id = ?", userID).First(&backupCode).Error; err != nil {
		return nil, err
	}
	return &backupCode, nil
}

func (r *BackupCodeRepository) CreateBackupCodes(ctx context.Context, codes []*models.BackupCode) error {
	return r.Db.WithContext(ctx).Create(&codes).Error
}

func (r *BackupCodeRepository) UpdateBackupCode(ctx context.Context, code *models.BackupCode) error {
	return r.Db.WithContext(ctx).Save(code).Error
}

func (r *BackupCodeRepository) DeleteBackupCode(ctx context.Context, code *models.BackupCode) error {
	return r.Db.WithContext(ctx).Delete(code).Error
}
