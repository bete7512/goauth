package twofactor

import (
	"context"
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
		tf.ID = uuid.New().String()
	}
	return r.db.WithContext(ctx).Create(tf).Error
}

func (r *twoFactorRepository) GetByUserID(ctx context.Context, userID string) (*models.TwoFactor, error) {
	var tf models.TwoFactor
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&tf).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &tf, nil
}

func (r *twoFactorRepository) Update(ctx context.Context, tf *models.TwoFactor) error {
	return r.db.WithContext(ctx).Save(tf).Error
}

func (r *twoFactorRepository) Delete(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.TwoFactor{}).Error
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
			code.ID = uuid.New().String()
		}
	}
	return r.db.WithContext(ctx).Create(codes).Error
}

func (r *backupCodeRepository) GetByUserID(ctx context.Context, userID string) ([]*models.BackupCode, error) {
	var codes []*models.BackupCode
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&codes).Error
	return codes, err
}

func (r *backupCodeRepository) GetUnusedByUserID(ctx context.Context, userID string) ([]*models.BackupCode, error) {
	var codes []*models.BackupCode
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND used = ?", userID, false).
		Find(&codes).Error
	return codes, err
}

func (r *backupCodeRepository) MarkUsed(ctx context.Context, id string) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&models.BackupCode{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		}).Error
}

func (r *backupCodeRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.BackupCode{}).Error
}
