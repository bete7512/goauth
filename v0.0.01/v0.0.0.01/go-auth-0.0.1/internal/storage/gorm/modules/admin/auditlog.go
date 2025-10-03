package admin

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/admin/models"
	"gorm.io/gorm"
)

// AuditLogRepository implements the admin module's AuditLogRepository interface
type AuditLogRepository struct {
	db *gorm.DB
}

// Ensure it implements the interface
var _ models.AuditLogRepository = (*AuditLogRepository)(nil)

func NewAuditLogRepository(db *gorm.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

func (r *AuditLogRepository) Create(ctx context.Context, log *models.AuditLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

func (r *AuditLogRepository) List(ctx context.Context, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

func (r *AuditLogRepository) FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

func (r *AuditLogRepository) FindByAction(ctx context.Context, action string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Where("action = ?", action).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}
