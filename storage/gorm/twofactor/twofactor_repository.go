package twofactor

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type twoFactorRepository struct {
	db *gorm.DB
}

func NewTwoFactorRepository(db *gorm.DB) models.TwoFactorRepository {
	return &twoFactorRepository{db: db}
}

func (r *twoFactorRepository) Create(ctx context.Context, tf *models.TwoFactor) error {
	if tf.ID == "" {
		tf.ID = uuid.Must(uuid.NewV7()).String()
	}
	if err := r.db.WithContext(ctx).Create(tf).Error; err != nil {
		return fmt.Errorf("twofactor_repository.Create: %w", err)
	}
	return nil
}

func (r *twoFactorRepository) GetByUserID(ctx context.Context, userID string) (*models.TwoFactor, error) {
	var tf models.TwoFactor
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&tf).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("twofactor_repository.GetByUserID: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("twofactor_repository.GetByUserID: %w", err)
	}
	return &tf, nil
}

func (r *twoFactorRepository) Update(ctx context.Context, tf *models.TwoFactor) error {
	if err := r.db.WithContext(ctx).Save(tf).Error; err != nil {
		return fmt.Errorf("twofactor_repository.Update: %w", err)
	}
	return nil
}

func (r *twoFactorRepository) Delete(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.TwoFactor{}).Error; err != nil {
		return fmt.Errorf("twofactor_repository.Delete: %w", err)
	}
	return nil
}

// Backup Code Repository

type backupCodeRepository struct {
	db *gorm.DB
}

func NewBackupCodeRepository(db *gorm.DB) models.BackupCodeRepository {
	return &backupCodeRepository{db: db}
}

func (r *backupCodeRepository) CreateBatch(ctx context.Context, codes []*models.BackupCode) error {
	for _, code := range codes {
		if code.ID == "" {
			code.ID = uuid.Must(uuid.NewV7()).String()
		}
	}
	if err := r.db.WithContext(ctx).Create(codes).Error; err != nil {
		return fmt.Errorf("backup_code_repository.CreateBatch: %w", err)
	}
	return nil
}

func (r *backupCodeRepository) GetByUserID(ctx context.Context, userID string) ([]*models.BackupCode, error) {
	var codes []*models.BackupCode
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&codes).Error; err != nil {
		return nil, fmt.Errorf("backup_code_repository.GetByUserID: %w", err)
	}
	return codes, nil
}

func (r *backupCodeRepository) GetUnusedByUserID(ctx context.Context, userID string) ([]*models.BackupCode, error) {
	var codes []*models.BackupCode
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND used = ?", userID, false).
		Find(&codes).Error; err != nil {
		return nil, fmt.Errorf("backup_code_repository.GetUnusedByUserID: %w", err)
	}
	return codes, nil
}

func (r *backupCodeRepository) MarkUsed(ctx context.Context, id string) error {
	now := time.Now()
	if err := r.db.WithContext(ctx).
		Model(&models.BackupCode{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		}).Error; err != nil {
		return fmt.Errorf("backup_code_repository.MarkUsed: %w", err)
	}
	return nil
}

func (r *backupCodeRepository) DeleteByUserID(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.BackupCode{}).Error; err != nil {
		return fmt.Errorf("backup_code_repository.DeleteByUserID: %w", err)
	}
	return nil
}
