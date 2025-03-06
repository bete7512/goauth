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

// func (f *PostgresRepositoryFactory) GetSessionRepository() repositories.SessionRepository {
// 	return NewSessionRepository(f.db)
// }

// func (f *PostgresRepositoryFactory) GetVerificationTokenRepository() repositories.VerificationTokenRepository {
// 	return NewVerificationTokenRepository(f.db)
// }

// func (f *PostgresRepositoryFactory) GetTwoFactorAuthRepository() repositories.TwoFactorAuthRepository {
// 	return NewTwoFactorAuthRepository(f.db)
// }
