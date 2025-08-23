package sqlserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type BackupCodeRepository struct {
	db *gorm.DB
}

func NewBackupCodeRepository(db *gorm.DB) interfaces.BackupCodeRepository {
	return &BackupCodeRepository{db: db}
}

func (b *BackupCodeRepository) GetBackupCodeByUserID(ctx context.Context, userID string) (*models.BackupCode, error) {
	var code models.BackupCode
	if err := b.db.Where("user_id = ?", userID).First(&code).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get backup code: %w", err)
	}
	return &code, nil
}

func (b *BackupCodeRepository) CreateBackupCodes(ctx context.Context, codes []*models.BackupCode) error {
	if err := b.db.Create(codes).Error; err != nil {
		return fmt.Errorf("failed to create backup codes: %w", err)
	}
	return nil
}

func (b *BackupCodeRepository) UpdateBackupCode(ctx context.Context, code *models.BackupCode) error {
	if err := b.db.Model(&models.BackupCode{}).Where("user_id = ?", code.UserID).Updates(code).Error; err != nil {
		return fmt.Errorf("failed to update backup code: %w", err)
	}
	return nil
}

func (b *BackupCodeRepository) DeleteBackupCode(ctx context.Context, code *models.BackupCode) error {
	if err := b.db.Delete(code).Error; err != nil {
		return fmt.Errorf("failed to delete backup code: %w", err)
	}
	return nil
}
