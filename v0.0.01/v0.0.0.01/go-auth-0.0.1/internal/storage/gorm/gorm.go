package gorm

import (
	"context"

	"github.com/bete7512/goauth/internal/storage/gorm/modules/core"
	"github.com/bete7512/goauth/pkg/storage"
	"gorm.io/gorm"
)

type GormStorage struct {
	db *gorm.DB
}

func NewGormStorage(db *gorm.DB) *GormStorage {
	return &GormStorage{db: db}
}

func (s *GormStorage) DB() interface{} {
	return s.db
}

func (s *GormStorage) AutoMigrate(ctx context.Context, models []interface{}) error {
	return s.db.WithContext(ctx).AutoMigrate(models...)
}

func (s *GormStorage) BeginTx(ctx context.Context) (storage.Transaction, error) {
	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &GormTransaction{tx: tx, userRepo: NewUserRepository(tx), sessionRepo: NewSessionRepository(tx)}, nil
}

func (s *GormStorage) UserRepository() storage.UserRepository {
	return core.NewUserRepository(s.db)
}

func (s *GormStorage) SessionRepository() storage.SessionRepository {
	return core.NewSessionRepository(s.db)
}

func (s *GormStorage) Repository(model interface{}) storage.Repository {
	return core.NewGenericRepository(s.db, model)
}
