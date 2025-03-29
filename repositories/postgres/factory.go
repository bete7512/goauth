package postgres

import (
	"github.com/bete7512/goauth/interfaces"
	"gorm.io/gorm"
)

type RepositoryFactory struct {
	db *gorm.DB
}

func NewRepositoryFactory(db *gorm.DB) interfaces.RepositoryFactory {
	return &RepositoryFactory{db: db}
}

func (f *RepositoryFactory) GetUserRepository() interfaces.UserRepository {
	return NewUserRepository(f.db)
}

func (f *RepositoryFactory) GetTokenRepository() interfaces.TokenRepository {
	return NewTokenRepository(f.db)
}