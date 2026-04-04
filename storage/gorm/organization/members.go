package organization

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/storage/gorm/helpers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Compile-time check: MemberRepo implements models.OrganizationMemberRepository
var _ models.OrganizationMemberRepository = (*MemberRepo)(nil)

// MemberRepo implements models.OrganizationMemberRepository using GORM
type MemberRepo struct {
	db *gorm.DB
}

// NewMemberRepo creates a new MemberRepo
func NewMemberRepo(db *gorm.DB) *MemberRepo {
	return &MemberRepo{db: db}
}

// Create creates a new organization member
func (r *MemberRepo) Create(ctx context.Context, member *models.OrganizationMember) error {
	if member.ID == "" {
		member.ID = uuid.Must(uuid.NewV7()).String()
	}
	if member.JoinedAt.IsZero() {
		member.JoinedAt = time.Now()
	}
	if err := r.db.WithContext(ctx).Create(member).Error; err != nil {
		return fmt.Errorf("member_repository.Create: %w", err)
	}
	return nil
}

// FindByOrgAndUser finds a membership by organization ID and user ID
func (r *MemberRepo) FindByOrgAndUser(ctx context.Context, orgID, userID string) (*models.OrganizationMember, error) {
	var member models.OrganizationMember
	err := r.db.WithContext(ctx).Where("org_id = ? AND user_id = ?", orgID, userID).First(&member).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("member_repository.FindByOrgAndUser: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("member_repository.FindByOrgAndUser: %w", err)
	}
	return &member, nil
}

// ListByOrg lists members of an organization with filtering, pagination, and sorting
func (r *MemberRepo) ListByOrg(ctx context.Context, orgID string, opts models.MemberListOpts) ([]*models.OrganizationMember, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.OrganizationMember{}).Where("org_id = ?", orgID)

	if opts.Role != "" {
		query = query.Where("role = ?", opts.Role)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("member_repository.ListByOrg count: %w", err)
	}

	var members []*models.OrganizationMember
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Find(&members).Error; err != nil {
		return nil, 0, fmt.Errorf("member_repository.ListByOrg find: %w", err)
	}
	return members, total, nil
}

// ListByUser lists all organization memberships for a user
func (r *MemberRepo) ListByUser(ctx context.Context, userID string) ([]*models.OrganizationMember, error) {
	var members []*models.OrganizationMember
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&members).Error; err != nil {
		return nil, fmt.Errorf("member_repository.ListByUser: %w", err)
	}
	return members, nil
}

// Update updates an existing organization member
func (r *MemberRepo) Update(ctx context.Context, member *models.OrganizationMember) error {
	now := time.Now()
	member.UpdatedAt = &now
	if err := r.db.WithContext(ctx).Save(member).Error; err != nil {
		return fmt.Errorf("member_repository.Update: %w", err)
	}
	return nil
}

// Delete deletes an organization member by ID
func (r *MemberRepo) Delete(ctx context.Context, id string) error {
	if err := r.db.WithContext(ctx).Delete(&models.OrganizationMember{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("member_repository.Delete: %w", err)
	}
	return nil
}

// DeleteByOrgAndUser deletes a membership by organization ID and user ID
func (r *MemberRepo) DeleteByOrgAndUser(ctx context.Context, orgID, userID string) error {
	if err := r.db.WithContext(ctx).Where("org_id = ? AND user_id = ?", orgID, userID).Delete(&models.OrganizationMember{}).Error; err != nil {
		return fmt.Errorf("member_repository.DeleteByOrgAndUser: %w", err)
	}
	return nil
}

// CountByOrg returns the number of members in an organization
func (r *MemberRepo) CountByOrg(ctx context.Context, orgID string) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.OrganizationMember{}).Where("org_id = ?", orgID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("member_repository.CountByOrg: %w", err)
	}
	return count, nil
}
