// Package rbac implements types.RBACStorage with GORM.
package rbac

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Compile-time check: GormRBACStorage implements types.RBACStorage
var _ types.RBACStorage = (*GormRBACStorage)(nil)

// GormRBACStorage implements types.RBACStorage using GORM
type GormRBACStorage struct {
	db          *gorm.DB
	roles       *RoleRepo
	assignments *AssignmentRepo
}

// NewRBACStorage creates a new GormRBACStorage
func NewRBACStorage(db *gorm.DB) *GormRBACStorage {
	return &GormRBACStorage{
		db:          db,
		roles:       NewRoleRepo(db),
		assignments: NewAssignmentRepo(db),
	}
}

// Roles returns the role repository
func (s *GormRBACStorage) Roles() models.RoleRepository {
	return s.roles
}

// Assignments returns the role assignment repository
func (s *GormRBACStorage) Assignments() models.RoleAssignmentRepository {
	return s.assignments
}

// WithTransaction executes a function within a database transaction
func (s *GormRBACStorage) WithTransaction(ctx context.Context, fn func(tx types.RBACStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(NewRBACStorage(tx))
	})
}
