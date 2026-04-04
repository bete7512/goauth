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
	if err := r.db.WithContext(ctx).Create(invitation).Error; err != nil {
		return fmt.Errorf("invitation_repository.Create: %w", err)
	}
	return nil
}

// FindByID finds an invitation by its ID
func (r *InvitationRepo) FindByID(ctx context.Context, id string) (*models.Invitation, error) {
	var invitation models.Invitation
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&invitation).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("invitation_repository.FindByID: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("invitation_repository.FindByID: %w", err)
	}
	return &invitation, nil
}

// FindByToken finds an invitation by its token
func (r *InvitationRepo) FindByToken(ctx context.Context, token string) (*models.Invitation, error) {
	var invitation models.Invitation
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&invitation).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("invitation_repository.FindByToken: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("invitation_repository.FindByToken: %w", err)
	}
	return &invitation, nil
}

// FindByOrgAndEmail finds a pending invitation by organization ID and email
func (r *InvitationRepo) FindByOrgAndEmail(ctx context.Context, orgID, email string) (*models.Invitation, error) {
	var invitation models.Invitation
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND email = ? AND status = ?", orgID, email, models.InvitationStatusPending).
		First(&invitation).Error
	if err == gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("invitation_repository.FindByOrgAndEmail: %w", models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("invitation_repository.FindByOrgAndEmail: %w", err)
	}
	return &invitation, nil
}

// ListByOrg lists invitations for an organization with filtering, pagination, and sorting
func (r *InvitationRepo) ListByOrg(ctx context.Context, orgID string, opts models.InvitationListOpts) ([]*models.Invitation, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.Invitation{}).Where("org_id = ?", orgID)

	if opts.Status != "" {
		query = query.Where("status = ?", opts.Status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("invitation_repository.ListByOrg count: %w", err)
	}

	var invitations []*models.Invitation
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Find(&invitations).Error; err != nil {
		return nil, 0, fmt.Errorf("invitation_repository.ListByOrg find: %w", err)
	}
	return invitations, total, nil
}

// ListPendingByEmail lists all pending, non-expired invitations for an email
func (r *InvitationRepo) ListPendingByEmail(ctx context.Context, email string) ([]*models.Invitation, error) {
	var invitations []*models.Invitation
	if err := r.db.WithContext(ctx).
		Where("email = ? AND status = ? AND expires_at > ?", email, models.InvitationStatusPending, time.Now()).
		Find(&invitations).Error; err != nil {
		return nil, fmt.Errorf("invitation_repository.ListPendingByEmail: %w", err)
	}
	return invitations, nil
}

// Update updates an existing invitation
func (r *InvitationRepo) Update(ctx context.Context, invitation *models.Invitation) error {
	if err := r.db.WithContext(ctx).Save(invitation).Error; err != nil {
		return fmt.Errorf("invitation_repository.Update: %w", err)
	}
	return nil
}

// Delete deletes an invitation by its ID
func (r *InvitationRepo) Delete(ctx context.Context, id string) error {
	if err := r.db.WithContext(ctx).Delete(&models.Invitation{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("invitation_repository.Delete: %w", err)
	}
	return nil
}

// DeleteExpired deletes all pending invitations that have expired
func (r *InvitationRepo) DeleteExpired(ctx context.Context) error {
	if err := r.db.WithContext(ctx).
		Where("status = ? AND expires_at < ?", models.InvitationStatusPending, time.Now()).
		Delete(&models.Invitation{}).Error; err != nil {
		return fmt.Errorf("invitation_repository.DeleteExpired: %w", err)
	}
	return nil
}
