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
	SaveTokenWithDeviceId(ctx context.Context, userID, token, deviceId string, tokenType models.TokenType, expiry time.Duration) error
	GetActiveTokenByUserIdAndType(ctx context.Context, userID string, tokenType models.TokenType) (*models.Token, error)
	GetActiveTokenByUserIdTypeAndDeviceId(ctx context.Context, userID string, tokenType models.TokenType, deviceId string) (*models.Token, error)
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

type RepositoryFactory interface {
	GetUserRepository() UserRepository
	GetTokenRepository() TokenRepository
}
