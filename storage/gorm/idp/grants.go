package idp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/storage/gorm/helpers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Compile-time check: GrantRepo implements models.IDPGrantRepository
var _ models.IDPGrantRepository = (*GrantRepo)(nil)

// GrantRepo implements models.IDPGrantRepository using GORM
type GrantRepo struct {
	db *gorm.DB
}

// NewGrantRepo creates a new GrantRepo
func NewGrantRepo(db *gorm.DB) *GrantRepo {
	return &GrantRepo{db: db}
}

// Create inserts a grant. It returns ErrConflict when the user already has a
// grant for the client.
func (r *GrantRepo) Create(ctx context.Context, grant *models.IDPGrant) error {
	if grant.ID == "" {
		grant.ID = uuid.Must(uuid.NewV7()).String()
	}
	now := time.Now().UTC()
	if grant.CreatedAt.IsZero() {
		grant.CreatedAt = now
	}
	if grant.UpdatedAt.IsZero() {
		grant.UpdatedAt = grant.CreatedAt
	}
	grant.CreatedAt, grant.UpdatedAt = grant.CreatedAt.UTC(), grant.UpdatedAt.UTC()
	grant.LastUsedAt = utcPtr(grant.LastUsedAt)
	// The insert runs in a transaction of its own (a savepoint when the
	// repository is already bound to one), so a failed insert leaves the
	// caller's transaction usable for the lookup below.
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Create(grant).Error
	})
	if err == nil {
		return nil
	}
	var existing int64
	if countErr := r.db.WithContext(ctx).Model(&models.IDPGrant{}).
		Where("user_id = ? AND client_id = ?", grant.UserID, grant.ClientID).Count(&existing).Error; countErr == nil && existing > 0 {
		return fmt.Errorf("idp_grant_repository.Create: %w", models.ErrConflict)
	}
	return fmt.Errorf("idp_grant_repository.Create: %w", err)
}

// Update saves the scopes of an existing grant.
func (r *GrantRepo) Update(ctx context.Context, grant *models.IDPGrant) error {
	grant.UpdatedAt = time.Now().UTC()
	result := r.db.WithContext(ctx).Model(&models.IDPGrant{}).Where("id = ?", grant.ID).
		Select("scopes", "updated_at").Updates(grant)
	if result.Error != nil {
		return fmt.Errorf("idp_grant_repository.Update: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("idp_grant_repository.Update: %w", models.ErrNotFound)
	}
	return nil
}

// FindByID finds a grant by its ID.
func (r *GrantRepo) FindByID(ctx context.Context, id string) (*models.IDPGrant, error) {
	return r.findOne(ctx, "FindByID", "id = ?", id)
}

// FindByUserAndClient finds the grant a user gave a client.
func (r *GrantRepo) FindByUserAndClient(ctx context.Context, userID, clientID string) (*models.IDPGrant, error) {
	grant, err := r.findOne(ctx, "FindByUserAndClient", "user_id = ? AND client_id = ?", userID, clientID)
	if err != nil {
		return nil, err
	}
	// Some collations compare text without regard to case; a client_id is
	// case-sensitive.
	if grant.ClientID != clientID {
		return nil, fmt.Errorf("idp_grant_repository.FindByUserAndClient: %w", models.ErrNotFound)
	}
	return grant, nil
}

func (r *GrantRepo) findOne(ctx context.Context, op, query string, args ...interface{}) (*models.IDPGrant, error) {
	var grant models.IDPGrant
	err := r.db.WithContext(ctx).Where(query, args...).First(&grant).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("idp_grant_repository.%s: %w", op, models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("idp_grant_repository.%s: %w", op, err)
	}
	return &grant, nil
}

// List retrieves grants with filtering, pagination, and sorting.
func (r *GrantRepo) List(ctx context.Context, opts models.IDPGrantListOpts) ([]*models.IDPGrant, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.IDPGrant{})
	if opts.UserID != "" {
		query = query.Where("user_id = ?", opts.UserID)
	}
	if opts.ClientID != "" {
		query = query.Where("client_id = ?", opts.ClientID)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("idp_grant_repository.List: %w", err)
	}
	var grants []*models.IDPGrant
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Find(&grants).Error; err != nil {
		return nil, 0, fmt.Errorf("idp_grant_repository.List: %w", err)
	}
	return grants, total, nil
}

// Delete removes a grant by its ID.
func (r *GrantRepo) Delete(ctx context.Context, id string) error {
	if err := r.db.WithContext(ctx).Delete(&models.IDPGrant{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("idp_grant_repository.Delete: %w", err)
	}
	return nil
}

// DeleteByClient removes every grant of a client and returns how many.
func (r *GrantRepo) DeleteByClient(ctx context.Context, clientID string) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&models.IDPGrant{}, "client_id = ?", clientID)
	if result.Error != nil {
		return 0, fmt.Errorf("idp_grant_repository.DeleteByClient: %w", result.Error)
	}
	return result.RowsAffected, nil
}

// DeleteByUser removes every grant of a user and returns how many.
func (r *GrantRepo) DeleteByUser(ctx context.Context, userID string) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&models.IDPGrant{}, "user_id = ?", userID)
	if result.Error != nil {
		return 0, fmt.Errorf("idp_grant_repository.DeleteByUser: %w", result.Error)
	}
	return result.RowsAffected, nil
}

// TouchLastUsed records when the grant last produced a token.
func (r *GrantRepo) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	if err := r.db.WithContext(ctx).Model(&models.IDPGrant{}).Where("id = ?", id).Update("last_used_at", at.UTC()).Error; err != nil {
		return fmt.Errorf("idp_grant_repository.TouchLastUsed: %w", err)
	}
	return nil
}
