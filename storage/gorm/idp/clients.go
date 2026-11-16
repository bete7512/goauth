package idp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/storage/gorm/helpers"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Compile-time check: ClientRepo implements models.IDPClientRepository
var _ models.IDPClientRepository = (*ClientRepo)(nil)

// ClientRepo implements models.IDPClientRepository using GORM
type ClientRepo struct {
	db *gorm.DB
}

// NewClientRepo creates a new ClientRepo
func NewClientRepo(db *gorm.DB) *ClientRepo {
	return &ClientRepo{db: db}
}

// Create inserts a client. It returns ErrConflict when the client_id is taken.
func (r *ClientRepo) Create(ctx context.Context, client *models.IDPClient) error {
	if client.ID == "" {
		client.ID = uuid.Must(uuid.NewV7()).String()
	}
	now := time.Now().UTC()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = now
	}
	if client.UpdatedAt.IsZero() {
		client.UpdatedAt = now
	}
	normalizeClientTimes(client)
	// The insert runs in a transaction of its own (a savepoint when the
	// repository is already bound to one), so a failed insert leaves the
	// caller's transaction usable for the lookup below.
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Create(client).Error
	})
	if err == nil {
		return nil
	}
	var taken int64
	if countErr := r.db.WithContext(ctx).Model(&models.IDPClient{}).Where("client_id = ?", client.ClientID).Count(&taken).Error; countErr == nil && taken > 0 {
		return fmt.Errorf("idp_client_repository.Create: %w", models.ErrConflict)
	}
	return fmt.Errorf("idp_client_repository.Create: %w", err)
}

// Update saves every field of an existing client.
func (r *ClientRepo) Update(ctx context.Context, client *models.IDPClient) error {
	client.UpdatedAt = time.Now().UTC()
	normalizeClientTimes(client)
	result := r.db.WithContext(ctx).Model(&models.IDPClient{}).Where("id = ?", client.ID).Select("*").Omit("id", "created_at").Updates(client)
	if result.Error != nil {
		return fmt.Errorf("idp_client_repository.Update: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("idp_client_repository.Update: %w", models.ErrNotFound)
	}
	return nil
}

// FindByID finds a client by its internal ID.
func (r *ClientRepo) FindByID(ctx context.Context, id string) (*models.IDPClient, error) {
	return r.findOne(ctx, "FindByID", "id = ?", id)
}

// FindByClientID finds a client by its public client_id.
func (r *ClientRepo) FindByClientID(ctx context.Context, clientID string) (*models.IDPClient, error) {
	client, err := r.findOne(ctx, "FindByClientID", "client_id = ?", clientID)
	if err != nil {
		return nil, err
	}
	// Some collations compare text without regard to case; a client_id is
	// case-sensitive.
	if client.ClientID != clientID {
		return nil, fmt.Errorf("idp_client_repository.FindByClientID: %w", models.ErrNotFound)
	}
	return client, nil
}

func (r *ClientRepo) findOne(ctx context.Context, op, query string, arg string) (*models.IDPClient, error) {
	var client models.IDPClient
	err := r.db.WithContext(ctx).Where(query, arg).First(&client).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("idp_client_repository.%s: %w", op, models.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("idp_client_repository.%s: %w", op, err)
	}
	return &client, nil
}

// FindByClientIDs finds the clients with the given public client_ids.
func (r *ClientRepo) FindByClientIDs(ctx context.Context, clientIDs []string) ([]*models.IDPClient, error) {
	if len(clientIDs) == 0 {
		return nil, nil
	}
	var clients []*models.IDPClient
	if err := r.db.WithContext(ctx).Where("client_id IN ?", clientIDs).Find(&clients).Error; err != nil {
		return nil, fmt.Errorf("idp_client_repository.FindByClientIDs: %w", err)
	}
	return clients, nil
}

// List retrieves clients with filtering, pagination, and sorting
func (r *ClientRepo) List(ctx context.Context, opts models.IDPClientListOpts) ([]*models.IDPClient, int64, error) {
	query := r.db.WithContext(ctx).Model(&models.IDPClient{})
	if opts.Managed != nil {
		query = query.Where("managed = ?", *opts.Managed)
	}
	if q := strings.TrimSpace(opts.Query); q != "" {
		like := helpers.ContainsPattern(q)
		query = query.Where("LOWER(name) LIKE ? ESCAPE '!' OR LOWER(client_id) LIKE ? ESCAPE '!'", like, like)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("idp_client_repository.List: %w", err)
	}
	var clients []*models.IDPClient
	if err := helpers.ApplyListingOpts(query, opts.ListingOpts).Find(&clients).Error; err != nil {
		return nil, 0, fmt.Errorf("idp_client_repository.List: %w", err)
	}
	return clients, total, nil
}

// Delete removes a client by its internal ID.
func (r *ClientRepo) Delete(ctx context.Context, id string) error {
	if err := r.db.WithContext(ctx).Delete(&models.IDPClient{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("idp_client_repository.Delete: %w", err)
	}
	return nil
}

// TouchLastUsed records when the client last obtained a token.
func (r *ClientRepo) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	if err := r.db.WithContext(ctx).Model(&models.IDPClient{}).Where("id = ?", id).Update("last_used_at", at.UTC()).Error; err != nil {
		return fmt.Errorf("idp_client_repository.TouchLastUsed: %w", err)
	}
	return nil
}

func normalizeClientTimes(client *models.IDPClient) {
	client.CreatedAt = client.CreatedAt.UTC()
	client.UpdatedAt = client.UpdatedAt.UTC()
	client.LastUsedAt = utcPtr(client.LastUsedAt)
}
