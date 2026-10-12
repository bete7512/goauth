package passkeys

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

type PasskeyStorage struct {
	db           *gorm.DB
	passkeysRepo models.PasskeyRepository
}

var _ types.PasskeyStorage = (*PasskeyStorage)(nil)

func NewPasskeyStorage(db *gorm.DB) *PasskeyStorage {
	return &PasskeyStorage{
		db:           db,
		passkeysRepo: NewPasskeyRepository(db),
	}
}

func (s *PasskeyStorage) Passkeys() models.PasskeyRepository {
	return s.passkeysRepo
}

func (s *PasskeyStorage) WithTransaction(ctx context.Context, fn func(tx types.PasskeyStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(&PasskeyStorage{
			db:           tx,
			passkeysRepo: NewPasskeyRepository(tx),
		})
	})
}
