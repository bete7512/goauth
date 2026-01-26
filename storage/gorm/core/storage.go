package core

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Compile-time check
var _ types.CoreStorage = (*GormCoreStorage)(nil)

// GormCoreStorage implements types.CoreStorage
type GormCoreStorage struct {
	db                 *gorm.DB
	users              *UserRepository
	tokens             *TokenRepository
	verificationTokens *VerificationTokenRepository
	extendedAttributes *ExtendedAttributeRepository
}

// NewCoreStorage creates a new core storage instance
func NewCoreStorage(db *gorm.DB) *GormCoreStorage {
	return &GormCoreStorage{
		db:                 db,
		users:              &UserRepository{db: db},
		tokens:             &TokenRepository{db: db},
		verificationTokens: &VerificationTokenRepository{db: db},
		extendedAttributes: &ExtendedAttributeRepository{db: db},
	}
}

func (s *GormCoreStorage) Users() models.UserRepository {
	return s.users
}

func (s *GormCoreStorage) Tokens() models.TokenRepository {
	return s.tokens
}

func (s *GormCoreStorage) VerificationTokens() models.VerificationTokenRepository {
	return s.verificationTokens
}

func (s *GormCoreStorage) ExtendedAttributes() models.ExtendedAttributeRepository {
	return s.extendedAttributes
}

func (s *GormCoreStorage) WithTransaction(ctx context.Context, fn func(tx types.CoreStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := NewCoreStorage(tx)
		return fn(txStorage)
	})
}
