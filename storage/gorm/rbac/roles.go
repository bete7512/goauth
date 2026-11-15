package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Compile-time check: RoleRepo implements models.RoleRepository
var _ models.RoleRepository = (*RoleRepo)(nil)

// RoleRepo implements models.RoleRepository using GORM
type RoleRepo struct {
	db *gorm.DB
}

// NewRoleRepo creates a new RoleRepo
func NewRoleRepo(db *gorm.DB) *RoleRepo {
	return &RoleRepo{db: db}
}

// Create stores a role. The unique index on (org_id, role_key) is what
// guarantees one role per key; a lost race is reported as ErrConflict.
func (r *RoleRepo) Create(ctx context.Context, role *models.Role) error {
	if role.ID == "" {
		role.ID = uuid.Must(uuid.NewV7()).String()
	}
	if role.CreatedAt.IsZero() {
		role.CreatedAt = time.Now()
	}
	if role.Grants == nil {
		role.Grants = models.StringList{}
	}
	if err := r.db.WithContext(ctx).Create(role).Error; err != nil {
		if _, findErr := r.FindByKey(ctx, role.OrgID, role.Key); findErr == nil {
			return fmt.Errorf("role_repository.Create: %w", models.ErrConflict)
		}
		return fmt.Errorf("role_repository.Create: %w", err)
	}
	return nil
}

// FindByKey finds a role by organization and key
func (r *RoleRepo) FindByKey(ctx context.Context, orgID, key string) (*models.Role, error) {
	var role models.Role
	err := r.db.WithContext(ctx).Where("org_id = ? AND role_key = ?", orgID, key).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("role_repository.FindByKey: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("role_repository.FindByKey: %w", err)
	}
	return &role, nil
}

// FindByKeys returns the roles of one organization that have these keys
func (r *RoleRepo) FindByKeys(ctx context.Context, orgID string, keys []string) ([]*models.Role, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	var roles []*models.Role
	if err := r.db.WithContext(ctx).Where("org_id = ? AND role_key IN ?", orgID, keys).Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("role_repository.FindByKeys: %w", err)
	}
	return roles, nil
}

// ListByOrg returns every role of an organization, oldest first
func (r *RoleRepo) ListByOrg(ctx context.Context, orgID string) ([]*models.Role, error) {
	var roles []*models.Role
	if err := r.db.WithContext(ctx).Where("org_id = ?", orgID).Order("created_at asc, id asc").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("role_repository.ListByOrg: %w", err)
	}
	return roles, nil
}

// CountByOrg returns the number of roles an organization has
func (r *RoleRepo) CountByOrg(ctx context.Context, orgID string) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.Role{}).Where("org_id = ?", orgID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("role_repository.CountByOrg: %w", err)
	}
	return count, nil
}

// Update changes the name, description and grants of a role. The key and the
// organization never change.
func (r *RoleRepo) Update(ctx context.Context, role *models.Role) error {
	now := time.Now()
	role.UpdatedAt = &now
	if role.Grants == nil {
		role.Grants = models.StringList{}
	}
	result := r.db.WithContext(ctx).Model(&models.Role{}).Where("id = ?", role.ID).
		Select("name", "description", "grants", "updated_at").Updates(role)
	if result.Error != nil {
		return fmt.Errorf("role_repository.Update: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("role_repository.Update: %w", models.ErrNotFound)
	}
	return nil
}

// Delete deletes a role by ID
func (r *RoleRepo) Delete(ctx context.Context, id string) error {
	if err := r.db.WithContext(ctx).Delete(&models.Role{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("role_repository.Delete: %w", err)
	}
	return nil
}

// DeleteByOrg deletes every role of an organization
func (r *RoleRepo) DeleteByOrg(ctx context.Context, orgID string) error {
	if err := r.db.WithContext(ctx).Where("org_id = ?", orgID).Delete(&models.Role{}).Error; err != nil {
		return fmt.Errorf("role_repository.DeleteByOrg: %w", err)
	}
	return nil
}
