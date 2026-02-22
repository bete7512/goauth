package twofactor

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

type TwoFactorStorage struct {
	db              *gorm.DB
	twoFactorRepo   models.TwoFactorRepository
	backupCodesRepo models.BackupCodeRepository
}

var _ types.TwoFactorStorage = (*TwoFactorStorage)(nil)

func NewTwoFactorStorage(db *gorm.DB) *TwoFactorStorage {
	return &TwoFactorStorage{
		db:              db,
		twoFactorRepo:   NewTwoFactorRepository(db),
		backupCodesRepo: NewBackupCodeRepository(db),
	}
}

func (s *TwoFactorStorage) TwoFactor() models.TwoFactorRepository {
	return s.twoFactorRepo
}

func (s *TwoFactorStorage) BackupCodes() models.BackupCodeRepository {
	return s.backupCodesRepo
}

func (s *TwoFactorStorage) WithTransaction(ctx context.Context, fn func(tx types.TwoFactorStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := &TwoFactorStorage{
			db:              tx,
			twoFactorRepo:   NewTwoFactorRepository(tx),
			backupCodesRepo: NewBackupCodeRepository(tx),
		}
		return fn(txStorage)
	})
}
