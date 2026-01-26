package session

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Compile-time check
var _ types.SessionStorage = (*GormSessionStorage)(nil)

// GormSessionStorage implements types.SessionStorage
type GormSessionStorage struct {
	db       *gorm.DB
	sessions *SessionRepository
}

// NewSessionStorage creates a new session storage instance
func NewSessionStorage(db *gorm.DB) *GormSessionStorage {
	return &GormSessionStorage{
		db:       db,
		sessions: &SessionRepository{db: db},
	}
}

func (s *GormSessionStorage) Sessions() models.SessionRepository {
	return s.sessions
}

func (s *GormSessionStorage) WithTransaction(ctx context.Context, fn func(tx types.SessionStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := NewSessionStorage(tx)
		return fn(txStorage)
	})
}
