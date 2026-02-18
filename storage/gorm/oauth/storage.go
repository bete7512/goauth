package oauth

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Compile-time check that GormOAuthStorage implements types.OAuthStorage
var _ types.OAuthStorage = (*GormOAuthStorage)(nil)

// GormOAuthStorage implements OAuthStorage using GORM
type GormOAuthStorage struct {
	db       *gorm.DB
	accounts *AccountRepository
}

// NewOAuthStorage creates a new GORM-based OAuth storage
func NewOAuthStorage(db *gorm.DB) *GormOAuthStorage {
	return &GormOAuthStorage{
		db:       db,
		accounts: NewAccountRepository(db),
	}
}

// Accounts returns the account repository
func (s *GormOAuthStorage) Accounts() models.AccountRepository {
	return s.accounts
}

// WithTransaction executes a function within a database transaction
func (s *GormOAuthStorage) WithTransaction(ctx context.Context, fn func(tx types.OAuthStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := NewOAuthStorage(tx)
		return fn(txStorage)
	})
}
