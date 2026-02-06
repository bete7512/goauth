package auditlog

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Compile-time check: GormAuditLogStorage implements types.AuditLogStorage
var _ types.AuditLogStorage = (*GormAuditLogStorage)(nil)

// GormAuditLogStorage implements types.AuditLogStorage using GORM
type GormAuditLogStorage struct {
	db              *gorm.DB
	auditLogRepo    *GormAuditLogRepository
}

// NewAuditLogStorage creates a new GormAuditLogStorage
func NewAuditLogStorage(db *gorm.DB) *GormAuditLogStorage {
	return &GormAuditLogStorage{
		db:              db,
		auditLogRepo:    NewAuditLogRepository(db),
	}
}

// AuditLogs returns the audit log repository
func (s *GormAuditLogStorage) AuditLogs() models.AuditLogRepository {
	return s.auditLogRepo
}

// WithTransaction executes a function within a database transaction
func (s *GormAuditLogStorage) WithTransaction(ctx context.Context, fn func(tx types.AuditLogStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := NewAuditLogStorage(tx)
		return fn(txStorage)
	})
}
