package organization

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/storage/gorm/helpers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Compile-time check: OrganizationRepo implements models.OrganizationRepository
var _ models.OrganizationRepository = (*OrganizationRepo)(nil)

// OrganizationRepo implements models.OrganizationRepository using GORM
type OrganizationRepo struct {
	db *gorm.DB
}

// NewOrganizationRepo creates a new OrganizationRepo
func NewOrganizationRepo(db *gorm.DB) *OrganizationRepo {
	return &OrganizationRepo{db: db}
}

// Create creates a new organization
func (r *OrganizationRepo) Create(ctx context.Context, org *models.Organization) error {
	if org.ID == "" {
		org.ID = uuid.New().String()
	}
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now()
	}
	return r.db.WithContext(ctx).Create(org).Error
}

// FindByID finds an organization by its ID
func (r *OrganizationRepo) FindByID(ctx context.Context, id string) (*models.Organization, error) {
	var org models.Organization
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&org).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &org, err
}

// FindBySlug finds an organization by its slug
func (r *OrganizationRepo) FindBySlug(ctx context.Context, slug string) (*models.Organization, error) {
	var org models.Organization
	err := r.db.WithContext(ctx).Where("slug = ?", slug).First(&org).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &org, err
}

// FindByOwnerID finds all organizations owned by a user
func (r *OrganizationRepo) FindByOwnerID(ctx context.Context, ownerID string) ([]*models.Organization, error) {
	var orgs []*models.Organization
	err := r.db.WithContext(ctx).Where("owner_id = ?", ownerID).Find(&orgs).Error
	return orgs, err
}

// List retrieves organizations with filtering, pagination, and sorting
func (r *OrganizationRepo) List(ctx context.Context, opts models.OrganizationListOpts) ([]*models.Organization, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.Organization{})

	if opts.OwnerID != "" {
		query = query.Where("owner_id = ?", opts.OwnerID)
	}

	if opts.Query != "" {
		search := "%" + opts.Query + "%"
		query = query.Where("name ILIKE ? OR slug ILIKE ?", search, search)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var orgs []*models.Organization
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Find(&orgs).Error; err != nil {
		return nil, 0, err
	}
	return orgs, total, nil
}

// Update updates an existing organization
func (r *OrganizationRepo) Update(ctx context.Context, org *models.Organization) error {
	now := time.Now()
	org.UpdatedAt = &now
	return r.db.WithContext(ctx).Save(org).Error
}

// Delete deletes an organization by its ID
func (r *OrganizationRepo) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.Organization{}, "id = ?", id).Error
}

// IsSlugAvailable checks if a slug is available (not taken by another organization)
func (r *OrganizationRepo) IsSlugAvailable(ctx context.Context, slug string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Organization{}).Where("slug = ?", slug).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count == 0, nil
}
