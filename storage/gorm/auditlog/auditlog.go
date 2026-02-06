package auditlog

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/storage/gorm/helpers"
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
func (r *GormAuditLogRepository) FindByActorID(ctx context.Context, actorID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, error) {
	var total int64
	baseQuery := r.db.WithContext(ctx).Model(&models.AuditLog{}).
		Where("actor_id = ?", actorID)

	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var logs []*models.AuditLog
	if err := helpers.ApplyListingOpts(baseQuery, opts.ListingOpts).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// FindByTargetID finds audit logs where the user was the target of actions
func (r *GormAuditLogRepository) FindByTargetID(ctx context.Context, targetID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, error) {
	var total int64
	baseQuery := r.db.WithContext(ctx).Model(&models.AuditLog{}).
		Where("target_id = ?", targetID)

	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var logs []*models.AuditLog
	if err := helpers.ApplyListingOpts(baseQuery, opts.ListingOpts).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// FindByAction finds audit logs by action type
func (r *GormAuditLogRepository) FindByAction(ctx context.Context, action string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, error) {
	var total int64
	baseQuery := r.db.WithContext(ctx).Model(&models.AuditLog{}).
		Where("action = ?", action)

	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var logs []*models.AuditLog
	if err := helpers.ApplyListingOpts(baseQuery, opts.ListingOpts).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// FindBySeverity finds audit logs by severity level
func (r *GormAuditLogRepository) FindBySeverity(ctx context.Context, severity string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, error) {
	var total int64
	baseQuery := r.db.WithContext(ctx).Model(&models.AuditLog{}).
		Where("severity = ?", severity)

	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var logs []*models.AuditLog
	if err := helpers.ApplyListingOpts(baseQuery, opts.ListingOpts).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// FindByOrganizationID finds audit logs for an organization (future)
func (r *GormAuditLogRepository) FindByOrganizationID(ctx context.Context, orgID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, error) {
	var total int64
	baseQuery := r.db.WithContext(ctx).Model(&models.AuditLog{}).
		Where("organization_id = ?", orgID)

	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var logs []*models.AuditLog
	if err := helpers.ApplyListingOpts(baseQuery, opts.ListingOpts).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// List retrieves all audit logs with pagination
func (r *GormAuditLogRepository) List(ctx context.Context, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, error) {
	var total int64
	if err := r.db.WithContext(ctx).Model(&models.AuditLog{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var logs []*models.AuditLog
	if err := helpers.ApplyListingOpts(r.db.WithContext(ctx), opts.ListingOpts).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
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
