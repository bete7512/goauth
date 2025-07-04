package sqlserver

import (
	"github.com/bete7512/goauth/pkg/interfaces"
	"gorm.io/gorm"
)

type RepositoryFactory struct {
	db *gorm.DB
}

func NewRepositoryFactory(db *gorm.DB) interfaces.RepositoryFactory {
	return &RepositoryFactory{
		db: db,
	}
}

func (f *RepositoryFactory) GetUserRepository() interfaces.UserRepository {
	return NewUserRepository(f.db)
}

func (f *RepositoryFactory) GetTokenRepository() interfaces.TokenRepository {
	return NewTokenRepository(f.db)
}

func (f *RepositoryFactory) GetAuditLogRepository() interfaces.AuditLogRepository {
	return NewAuditLogRepository(f.db)
}

func (f *RepositoryFactory) GetTotpSecretRepository() interfaces.TotpSecretRepository {
	return NewTotpSecretRepository(f.db)
}

func (f *RepositoryFactory) GetOauthAccountRepository() interfaces.OauthAccountRepository {
	return NewOauthAccountRepository(f.db)
}

func (f *RepositoryFactory) GetBackupCodeRepository() interfaces.BackupCodeRepository {
	return NewBackupCodeRepository(f.db)
}

func (f *RepositoryFactory) GetSessionRepository() interfaces.SessionRepository {
	return NewSessionRepository(f.db)
}
