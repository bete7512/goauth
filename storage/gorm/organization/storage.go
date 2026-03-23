package organization

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Compile-time check: GormOrganizationStorage implements types.OrganizationStorage
var _ types.OrganizationStorage = (*GormOrganizationStorage)(nil)

// GormOrganizationStorage implements types.OrganizationStorage using GORM
type GormOrganizationStorage struct {
	db          *gorm.DB
	orgs        *OrganizationRepo
	members     *MemberRepo
	invitations *InvitationRepo
}

// NewOrganizationStorage creates a new GormOrganizationStorage
func NewOrganizationStorage(db *gorm.DB) *GormOrganizationStorage {
	return &GormOrganizationStorage{
		db:          db,
		orgs:        NewOrganizationRepo(db),
		members:     NewMemberRepo(db),
		invitations: NewInvitationRepo(db),
	}
}

// Organizations returns the organization repository
func (s *GormOrganizationStorage) Organizations() models.OrganizationRepository {
	return s.orgs
}

// Members returns the organization member repository
func (s *GormOrganizationStorage) Members() models.OrganizationMemberRepository {
	return s.members
}

// Invitations returns the invitation repository
func (s *GormOrganizationStorage) Invitations() models.InvitationRepository {
	return s.invitations
}

// WithTransaction executes a function within a database transaction
func (s *GormOrganizationStorage) WithTransaction(ctx context.Context, fn func(tx types.OrganizationStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := NewOrganizationStorage(tx)
		return fn(txStorage)
	})
}
