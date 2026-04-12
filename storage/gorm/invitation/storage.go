package invitation

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Compile-time check: GormInvitationStorage implements types.InvitationStorage
var _ types.InvitationStorage = (*GormInvitationStorage)(nil)

// GormInvitationStorage implements types.InvitationStorage using GORM
type GormInvitationStorage struct {
	db          *gorm.DB
	invitations *InvitationRepo
}

// NewInvitationStorage creates a new GormInvitationStorage
func NewInvitationStorage(db *gorm.DB) *GormInvitationStorage {
	return &GormInvitationStorage{
		db:          db,
		invitations: NewInvitationRepo(db),
	}
}

// Invitations returns the invitation repository
func (s *GormInvitationStorage) Invitations() models.InvitationRepository {
	return s.invitations
}

// WithTransaction executes a function within a database transaction
func (s *GormInvitationStorage) WithTransaction(ctx context.Context, fn func(tx types.InvitationStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := NewInvitationStorage(tx)
		return fn(txStorage)
	})
}
