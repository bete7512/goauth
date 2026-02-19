package gorm

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

type twoFactorStorage struct {
	db               *gorm.DB
	twoFactorRepo    models.TwoFactorRepository
	backupCodesRepo  models.BackupCodeRepository
}

func NewTwoFactorStorage(db *gorm.DB) types.TwoFactorStorage {
	return &twoFactorStorage{
		db:              db,
		twoFactorRepo:   NewTwoFactorRepository(db),
		backupCodesRepo: NewBackupCodeRepository(db),
	}
}

func (s *twoFactorStorage) TwoFactor() models.TwoFactorRepository {
	return s.twoFactorRepo
}

func (s *twoFactorStorage) BackupCodes() models.BackupCodeRepository {
	return s.backupCodesRepo
}

func (s *twoFactorStorage) WithTransaction(ctx context.Context, fn func(tx types.TwoFactorStorage) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txStorage := &twoFactorStorage{
			db:              tx,
			twoFactorRepo:   NewTwoFactorRepository(tx),
			backupCodesRepo: NewBackupCodeRepository(tx),
		}
		return fn(txStorage)
	})
}
