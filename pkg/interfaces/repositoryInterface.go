package interfaces

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
)

type Pagination struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
}
type Sort struct {
	Field     string `json:"field"`
	Direction string `json:"direction"`
}

type Filter struct {
	Pagination
	Sort
	Search string `json:"search"`
	UserId string `json:"user_id"`
	Email  string `json:"email"`
}

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	UpsertUserByEmail(ctx context.Context, user *models.User) error
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, user *models.User) error
	GetAllUsers(ctx context.Context, filter Filter) ([]*models.User, int64, error)
}

type TokenRepository interface {
	SaveToken(ctx context.Context, userID, token string, tokenType models.TokenType, expiry time.Duration) error
	GetActiveTokenByUserIdAndType(ctx context.Context, userID string, tokenType models.TokenType) (*models.Token, error)
	RevokeToken(ctx context.Context, tokenId string) error
	RevokeAllTokens(ctx context.Context, userID string, tokenType models.TokenType) error
	CleanExpiredTokens(ctx context.Context, tokenType models.TokenType) error
}

type AuditLogRepository interface {
	SaveAuditLog(ctx context.Context, log *models.AuditLog) error
	GetAuditLogs(ctx context.Context, filter Filter) ([]*models.AuditLog, int64, error)
	GetAuditLogByID(ctx context.Context, id string) (*models.AuditLog, error)
	DeleteAuditLog(ctx context.Context, log *models.AuditLog) error
}

type TotpSecretRepository interface {
	GetTOTPSecretByUserID(ctx context.Context, userID string) (*models.TotpSecret, error)
	CreateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error
	UpdateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error
	DeleteTOTPSecret(ctx context.Context, secret *models.TotpSecret) error
}

type OauthAccountRepository interface {
	GetOauthAccountByUserID(ctx context.Context, userID string) (*models.OauthAccount, error)
	CreateOauthAccount(ctx context.Context, account *models.OauthAccount) error
	UpdateOauthAccount(ctx context.Context, account *models.OauthAccount) error
	DeleteOauthAccount(ctx context.Context, account *models.OauthAccount) error
}

type BackupCodeRepository interface {
	GetBackupCodeByUserID(ctx context.Context, userID string) (*models.BackupCode, error)
	CreateBackupCodes(ctx context.Context, codes []*models.BackupCode) error
	UpdateBackupCode(ctx context.Context, code *models.BackupCode) error
	DeleteBackupCode(ctx context.Context, code *models.BackupCode) error
}

type SessionRepository interface {
	GetSessionByUserID(ctx context.Context, userID string) ([]models.Session, error)
	GetSessionBySessionID(ctx context.Context, sessionID string) (*models.Session, error)
	CreateSession(ctx context.Context, session *models.Session) error
	UpdateSession(ctx context.Context, session *models.Session) error
	DeleteAllUserSessions(ctx context.Context, userID string) error
	DeleteSession(ctx context.Context, session *models.Session) error
}

type RepositoryFactory interface {
	GetUserRepository() UserRepository
	GetTokenRepository() TokenRepository
	GetAuditLogRepository() AuditLogRepository
	GetTotpSecretRepository() TotpSecretRepository
	GetOauthAccountRepository() OauthAccountRepository
	GetBackupCodeRepository() BackupCodeRepository
	GetSessionRepository() SessionRepository
}
