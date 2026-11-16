// Package idp implements types.IDPStorage with GORM.
package idp

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Compile-time check: GormIDPStorage implements types.IDPStorage
var _ types.IDPStorage = (*GormIDPStorage)(nil)

// GormIDPStorage implements types.IDPStorage using GORM
type GormIDPStorage struct {
	db      *gorm.DB
	clients *ClientRepo
	grants  *GrantRepo
}

// NewIDPStorage creates a new GormIDPStorage
func NewIDPStorage(db *gorm.DB) *GormIDPStorage {
	return &GormIDPStorage{
		db:      db,
		clients: NewClientRepo(db),
		grants:  NewGrantRepo(db),
	}
}

// Clients returns the client application repository
func (s *GormIDPStorage) Clients() models.IDPClientRepository { return s.clients }

// Grants returns the grant repository
func (s *GormIDPStorage) Grants() models.IDPGrantRepository { return s.grants }

// WithTransaction executes a function within a database transaction
func (s *GormIDPStorage) WithTransaction(ctx context.Context, fn func(tx types.IDPStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(NewIDPStorage(tx))
	})
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	utc := t.UTC()
	return &utc
}
