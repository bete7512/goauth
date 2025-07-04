package sqlserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"gorm.io/gorm"
)

type AuditLogRepository struct {
	db *gorm.DB
}

func NewAuditLogRepository(db *gorm.DB) interfaces.AuditLogRepository {
	return &AuditLogRepository{db: db}
}

func (a *AuditLogRepository) SaveAuditLog(ctx context.Context, log *models.AuditLog) error {
	if err := a.db.Create(log).Error; err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}
	return nil
}

func (a *AuditLogRepository) GetAuditLogs(ctx context.Context, filter interfaces.Filter) ([]*models.AuditLog, int64, error) {
	var logs []*models.AuditLog
	var total int64

	if err := a.db.Model(&models.AuditLog{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	if filter.Page > 0 && filter.Limit > 0 {
		offset := (filter.Page - 1) * filter.Limit
		if err := a.db.Offset(offset).Limit(filter.Limit).Find(&logs).Error; err != nil {
			return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
		}
	} else {
		if err := a.db.Find(&logs).Error; err != nil {
			return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
		}
	}

	return logs, total, nil
}

func (a *AuditLogRepository) GetAuditLogByID(ctx context.Context, id string) (*models.AuditLog, error) {
	var log models.AuditLog
	if err := a.db.Where("id = ?", id).First(&log).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get audit log by id: %w", err)
	}
	return &log, nil
}

func (a *AuditLogRepository) DeleteAuditLog(ctx context.Context, log *models.AuditLog) error {
	if err := a.db.Delete(log).Error; err != nil {
		return fmt.Errorf("failed to delete audit log: %w", err)
	}
	return nil
}
