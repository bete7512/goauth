package postgres

import (
	"context"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type AuditLogRepository struct {
	Db *gorm.DB
}

func NewAuditLogRepository(db *gorm.DB) *AuditLogRepository {
	return &AuditLogRepository{Db: db}
}

func (r *AuditLogRepository) GetAuditLogByID(ctx context.Context, id string) (*models.AuditLog, error) {
	var auditLog models.AuditLog
	if err := r.Db.WithContext(ctx).Where("id = ?", id).First(&auditLog).Error; err != nil {
		return nil, err
	}
	return &auditLog, nil
}

func (r *AuditLogRepository) GetAuditLogs(ctx context.Context, filter interfaces.Filter) ([]*models.AuditLog, int64, error) {
	var auditLogs []*models.AuditLog
	var total int64

	if err := r.Db.WithContext(ctx).Model(&models.AuditLog{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if err := r.Db.WithContext(ctx).Where("user_id = ?", filter.UserId).Order("created_at DESC").Limit(filter.Limit).Offset((filter.Page - 1) * filter.Limit).Find(&auditLogs).Error; err != nil {
		return nil, 0, err
	}

	return auditLogs, total, nil
}

func (r *AuditLogRepository) SaveAuditLog(ctx context.Context, log *models.AuditLog) error {
	return r.Db.WithContext(ctx).Create(log).Error
}

func (r *AuditLogRepository) DeleteAuditLog(ctx context.Context, log *models.AuditLog) error {
	return r.Db.WithContext(ctx).Delete(log).Error
}
