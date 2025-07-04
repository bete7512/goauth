package mongodb

import (
	"github.com/bete7512/goauth/pkg/interfaces"
	"go.mongodb.org/mongo-driver/mongo"
)

type RepositoryFactory struct {
	client *mongo.Client
}

func NewRepositoryFactory(client *mongo.Client) interfaces.RepositoryFactory {
	return &RepositoryFactory{
		client: client,
	}
}

func (f *RepositoryFactory) GetUserRepository() interfaces.UserRepository {
	return NewUserRepository(f.client)
}

func (f *RepositoryFactory) GetTokenRepository() interfaces.TokenRepository {
	return NewTokenRepository(f.client)
}

func (f *RepositoryFactory) GetAuditLogRepository() interfaces.AuditLogRepository {
	return NewAuditLogRepository(f.client)
}

func (f *RepositoryFactory) GetTotpSecretRepository() interfaces.TotpSecretRepository {
	return NewTotpSecretRepository(f.client)
}

func (f *RepositoryFactory) GetOauthAccountRepository() interfaces.OauthAccountRepository {
	return NewOauthAccountRepository(f.client)
}

func (f *RepositoryFactory) GetBackupCodeRepository() interfaces.BackupCodeRepository {
	return NewBackupCodeRepository(f.client)
}

func (f *RepositoryFactory) GetSessionRepository() interfaces.SessionRepository {
	return NewSessionRepository(f.client)
}
