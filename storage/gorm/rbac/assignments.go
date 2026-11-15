package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/storage/gorm/helpers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Compile-time check: AssignmentRepo implements models.RoleAssignmentRepository
var _ models.RoleAssignmentRepository = (*AssignmentRepo)(nil)

// AssignmentRepo implements models.RoleAssignmentRepository using GORM
type AssignmentRepo struct {
	db *gorm.DB
}

// NewAssignmentRepo creates a new AssignmentRepo
func NewAssignmentRepo(db *gorm.DB) *AssignmentRepo {
	return &AssignmentRepo{db: db}
}

// Create stores an assignment. The unique index on (user_id, scope_type,
// scope_id, role_key) guarantees a user holds a role once per scope; a
// duplicate is reported as ErrConflict.
func (r *AssignmentRepo) Create(ctx context.Context, assignment *models.RoleAssignment) error {
	if assignment.ID == "" {
		assignment.ID = uuid.Must(uuid.NewV7()).String()
	}
	if assignment.CreatedAt.IsZero() {
		assignment.CreatedAt = time.Now()
	}
	if err := r.db.WithContext(ctx).Create(assignment).Error; err != nil {
		var count int64
		countErr := r.db.WithContext(ctx).Model(&models.RoleAssignment{}).
			Where("user_id = ? AND scope_type = ? AND scope_id = ? AND role_key = ?",
				assignment.UserID, assignment.ScopeType, assignment.ScopeID, assignment.RoleKey).
			Count(&count).Error
		if countErr == nil && count > 0 {
			return fmt.Errorf("assignment_repository.Create: %w", models.ErrConflict)
		}
		return fmt.Errorf("assignment_repository.Create: %w", err)
	}
	return nil
}

// ListByUser returns the user's assignments in the given scopes. It is the
// query behind every permission check, served by the unique index.
func (r *AssignmentRepo) ListByUser(ctx context.Context, userID string, scopes []models.RoleScopeRef) ([]*models.RoleAssignment, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	scopeFilter := r.db.Where("scope_type = ? AND scope_id = ?", scopes[0].Type, scopes[0].ID)
	for _, scope := range scopes[1:] {
		scopeFilter = scopeFilter.Or("scope_type = ? AND scope_id = ?", scope.Type, scope.ID)
	}
	var assignments []*models.RoleAssignment
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Where(scopeFilter).
		Order("created_at asc, id asc").Find(&assignments).Error
	if err != nil {
		return nil, fmt.Errorf("assignment_repository.ListByUser: %w", err)
	}
	return assignments, nil
}

// ListByScope lists the assignments made in one scope with filtering,
// pagination and sorting
func (r *AssignmentRepo) ListByScope(ctx context.Context, scopeType, scopeID string, opts models.RoleAssignmentListOpts) ([]*models.RoleAssignment, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.RoleAssignment{}).
		Where("scope_type = ? AND scope_id = ?", scopeType, scopeID)
	if opts.UserID != "" {
		query = query.Where("user_id = ?", opts.UserID)
	}
	if opts.RoleKey != "" {
		query = query.Where("role_key = ?", opts.RoleKey)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("assignment_repository.ListByScope count: %w", err)
	}

	var assignments []*models.RoleAssignment
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Find(&assignments).Error; err != nil {
		return nil, 0, fmt.Errorf("assignment_repository.ListByScope find: %w", err)
	}
	return assignments, total, nil
}

// Delete removes one role from a user in one scope
func (r *AssignmentRepo) Delete(ctx context.Context, userID, scopeType, scopeID, roleKey string) error {
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND scope_type = ? AND scope_id = ? AND role_key = ?", userID, scopeType, scopeID, roleKey).
		Delete(&models.RoleAssignment{}).Error
	if err != nil {
		return fmt.Errorf("assignment_repository.Delete: %w", err)
	}
	return nil
}

// DeleteByRole removes a role from everyone who holds it in one scope
func (r *AssignmentRepo) DeleteByRole(ctx context.Context, scopeType, scopeID, roleKey string) error {
	err := r.db.WithContext(ctx).
		Where("scope_type = ? AND scope_id = ? AND role_key = ?", scopeType, scopeID, roleKey).
		Delete(&models.RoleAssignment{}).Error
	if err != nil {
		return fmt.Errorf("assignment_repository.DeleteByRole: %w", err)
	}
	return nil
}

// DeleteByUserAndScope removes every role a user holds in one scope
func (r *AssignmentRepo) DeleteByUserAndScope(ctx context.Context, userID, scopeType, scopeID string) error {
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND scope_type = ? AND scope_id = ?", userID, scopeType, scopeID).
		Delete(&models.RoleAssignment{}).Error
	if err != nil {
		return fmt.Errorf("assignment_repository.DeleteByUserAndScope: %w", err)
	}
	return nil
}

// DeleteByUser removes every role a user holds anywhere
func (r *AssignmentRepo) DeleteByUser(ctx context.Context, userID string) error {
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&models.RoleAssignment{}).Error; err != nil {
		return fmt.Errorf("assignment_repository.DeleteByUser: %w", err)
	}
	return nil
}

// DeleteByScope removes every assignment made in one scope
func (r *AssignmentRepo) DeleteByScope(ctx context.Context, scopeType, scopeID string) error {
	err := r.db.WithContext(ctx).Where("scope_type = ? AND scope_id = ?", scopeType, scopeID).
		Delete(&models.RoleAssignment{}).Error
	if err != nil {
		return fmt.Errorf("assignment_repository.DeleteByScope: %w", err)
	}
	return nil
}
