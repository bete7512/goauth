package core

import (
	"context"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/models"
	"gorm.io/gorm"
)

type VerificationTokenRepository struct {
	db *gorm.DB
}

var _ models.VerificationTokenRepository = (*VerificationTokenRepository)(nil)

func NewVerificationTokenRepository(db *gorm.DB) *VerificationTokenRepository {
	return &VerificationTokenRepository{db: db}
}

func (r *VerificationTokenRepository) Create(ctx context.Context, token *models.VerificationToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *VerificationTokenRepository) FindByToken(ctx context.Context, token string) (*models.VerificationToken, error) {
	var vToken *models.VerificationToken
	err := r.db.WithContext(ctx).Where("token = ? AND used = ? AND expires_at > ?", token, false, time.Now()).First(&vToken).Error
	return vToken, err
}

func (r *VerificationTokenRepository) FindByCode(ctx context.Context, code, tokenType string) (*models.VerificationToken, error) {
	var vToken *models.VerificationToken
	err := r.db.WithContext(ctx).Where("code = ? AND type = ? AND used = ? AND expires_at > ?", code, tokenType, false, time.Now()).First(&vToken).Error
	return vToken, err
}

func (r *VerificationTokenRepository) FindByEmailAndType(ctx context.Context, email, tokenType string) (*models.VerificationToken, error) {
	var vToken *models.VerificationToken
	err := r.db.WithContext(ctx).Where("email = ? AND type = ? AND used = ? AND expires_at > ?", email, tokenType, false, time.Now()).Order("created_at DESC").First(&vToken).Error
	return vToken, err
}

func (r *VerificationTokenRepository) FindByPhoneAndType(ctx context.Context, phone, tokenType string) (*models.VerificationToken, error) {
	var vToken *models.VerificationToken
	err := r.db.WithContext(ctx).Where("phone = ? AND type = ? AND used = ? AND expires_at > ?", phone, tokenType, false, time.Now()).Order("created_at DESC").First(&vToken).Error
	return vToken, err
}

func (r *VerificationTokenRepository) MarkAsUsed(ctx context.Context, id string) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&models.VerificationToken{}).Where("id = ?", id).Updates(map[string]interface{}{
		"used":    true,
		"used_at": &now,
	}).Error
}

func (r *VerificationTokenRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.VerificationToken{}).Error
}

func (r *VerificationTokenRepository) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.VerificationToken{}, "id = ?", id).Error
}
