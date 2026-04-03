package organization

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/storage/gorm/helpers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Compile-time check: InvitationRepo implements models.InvitationRepository
var _ models.InvitationRepository = (*InvitationRepo)(nil)

// InvitationRepo implements models.InvitationRepository using GORM
type InvitationRepo struct {
	db *gorm.DB
}

// NewInvitationRepo creates a new InvitationRepo
func NewInvitationRepo(db *gorm.DB) *InvitationRepo {
	return &InvitationRepo{db: db}
}

// Create creates a new invitation
func (r *InvitationRepo) Create(ctx context.Context, invitation *models.Invitation) error {
	if invitation.ID == "" {
		invitation.ID = uuid.Must(uuid.NewV7()).String()
	}
	if invitation.CreatedAt.IsZero() {
		invitation.CreatedAt = time.Now()
	}
	return r.db.WithContext(ctx).Create(invitation).Error
}

// FindByID finds an invitation by its ID
func (r *InvitationRepo) FindByID(ctx context.Context, id string) (*models.Invitation, error) {
	var invitation models.Invitation
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&invitation).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &invitation, err
}

// FindByToken finds an invitation by its token
func (r *InvitationRepo) FindByToken(ctx context.Context, token string) (*models.Invitation, error) {
	var invitation models.Invitation
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&invitation).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &invitation, err
}

// FindByOrgAndEmail finds a pending invitation by organization ID and email
func (r *InvitationRepo) FindByOrgAndEmail(ctx context.Context, orgID, email string) (*models.Invitation, error) {
	var invitation models.Invitation
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND email = ? AND status = ?", orgID, email, models.InvitationStatusPending).
		First(&invitation).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &invitation, err
}

// ListByOrg lists invitations for an organization with filtering, pagination, and sorting
func (r *InvitationRepo) ListByOrg(ctx context.Context, orgID string, opts models.InvitationListOpts) ([]*models.Invitation, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.Invitation{}).Where("org_id = ?", orgID)

	if opts.Status != "" {
		query = query.Where("status = ?", opts.Status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var invitations []*models.Invitation
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Find(&invitations).Error; err != nil {
		return nil, 0, err
	}
	return invitations, total, nil
}

// ListPendingByEmail lists all pending, non-expired invitations for an email
func (r *InvitationRepo) ListPendingByEmail(ctx context.Context, email string) ([]*models.Invitation, error) {
	var invitations []*models.Invitation
	err := r.db.WithContext(ctx).
		Where("email = ? AND status = ? AND expires_at > ?", email, models.InvitationStatusPending, time.Now()).
		Find(&invitations).Error
	return invitations, err
}

// Update updates an existing invitation
func (r *InvitationRepo) Update(ctx context.Context, invitation *models.Invitation) error {
	return r.db.WithContext(ctx).Save(invitation).Error
}

// Delete deletes an invitation by its ID
func (r *InvitationRepo) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.Invitation{}, "id = ?", id).Error
}

// DeleteExpired deletes all pending invitations that have expired
func (r *InvitationRepo) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("status = ? AND expires_at < ?", models.InvitationStatusPending, time.Now()).
		Delete(&models.Invitation{}).Error
}
