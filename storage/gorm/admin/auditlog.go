package admin

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Compile-time check: GormAuditLogRepository implements models.AuditLogRepository
var _ models.AuditLogRepository = (*GormAuditLogRepository)(nil)

// GormAuditLogRepository implements AuditLogRepository using GORM
type GormAuditLogRepository struct {
	db *gorm.DB
}

// NewAuditLogRepository creates a new GormAuditLogRepository
func NewAuditLogRepository(db *gorm.DB) *GormAuditLogRepository {
	return &GormAuditLogRepository{db: db}
}

// Create creates a new audit log entry
func (r *GormAuditLogRepository) Create(ctx context.Context, log *models.AuditLog) error {
	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	// Set default values
	if log.ActorType == "" {
		log.ActorType = "user"
	}
	if log.Severity == "" {
		log.Severity = "info"
	}
	return r.db.WithContext(ctx).Create(log).Error
}

// FindByActorID finds audit logs by the user who performed actions
func (r *GormAuditLogRepository) FindByActorID(ctx context.Context, actorID string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Where("actor_id = ?", actorID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// FindByTargetID finds audit logs where the user was the target of actions
func (r *GormAuditLogRepository) FindByTargetID(ctx context.Context, targetID string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Where("target_id = ?", targetID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// FindByAction finds audit logs by action type
func (r *GormAuditLogRepository) FindByAction(ctx context.Context, action string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Where("action = ?", action).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// FindBySeverity finds audit logs by severity level
func (r *GormAuditLogRepository) FindBySeverity(ctx context.Context, severity string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Where("severity = ?", severity).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// FindByOrganizationID finds audit logs for an organization (future)
func (r *GormAuditLogRepository) FindByOrganizationID(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Where("organization_id = ?", orgID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// List retrieves all audit logs with pagination
func (r *GormAuditLogRepository) List(ctx context.Context, limit, offset int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// DeleteOlderThan deletes audit logs older than the specified time
func (r *GormAuditLogRepository) DeleteOlderThan(ctx context.Context, before time.Time) error {
	return r.db.WithContext(ctx).
		Where("created_at < ?", before).
		Delete(&models.AuditLog{}).Error
}

// DeleteByActionOlderThan deletes audit logs for specific action older than specified time
func (r *GormAuditLogRepository) DeleteByActionOlderThan(ctx context.Context, action string, before time.Time) error {
	return r.db.WithContext(ctx).
		Where("action LIKE ? AND created_at < ?", action+"%", before).
		Delete(&models.AuditLog{}).Error
}
