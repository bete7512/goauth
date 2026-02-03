package admin

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Compile-time check: GormAdminStorage implements types.AdminStorage
var _ types.AdminStorage = (*GormAdminStorage)(nil)

// GormAdminStorage implements types.AdminStorage using GORM
type GormAdminStorage struct {
	db              *gorm.DB
	auditLogRepo    *GormAuditLogRepository
}

// NewAdminStorage creates a new GormAdminStorage
func NewAdminStorage(db *gorm.DB) *GormAdminStorage {
	return &GormAdminStorage{
		db:              db,
		auditLogRepo:    NewAuditLogRepository(db),
	}
}

// AuditLogs returns the audit log repository
func (s *GormAdminStorage) AuditLogs() models.AuditLogRepository {
	return s.auditLogRepo
}

// WithTransaction executes a function within a database transaction
func (s *GormAdminStorage) WithTransaction(ctx context.Context, fn func(tx types.AdminStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := NewAdminStorage(tx)
		return fn(txStorage)
	})
}
