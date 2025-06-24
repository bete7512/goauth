package interfaces

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/types"
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
	CreateUser(ctx context.Context, user *types.User) error
	UpsertUserByEmail(ctx context.Context, user *types.User) error
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*types.User, error)
	GetUserByEmail(ctx context.Context, email string) (*types.User, error)
	GetUserByID(ctx context.Context, id string) (*types.User, error)
	UpdateUser(ctx context.Context, user *types.User) error
	DeleteUser(ctx context.Context, user *types.User) error
	GetAllUsers(ctx context.Context, filter Filter) ([]*types.User, int64, error)
}

type TokenRepository interface {
	SaveToken(ctx context.Context, userID, token string, tokenType types.TokenType, expiry time.Duration) error
	SaveTokenWithDeviceId(ctx context.Context, userID, token, deviceId string, tokenType types.TokenType, expiry time.Duration) error
	GetActiveTokenByUserIdAndType(ctx context.Context, userID string, tokenType types.TokenType) (*types.Token, error)
	GetActiveTokenByUserIdTypeAndDeviceId(ctx context.Context, userID string, tokenType types.TokenType, deviceId string) (*types.Token, error)
	RevokeToken(ctx context.Context, tokenId string) error
	RevokeAllTokens(ctx context.Context, userID string, tokenType types.TokenType) error
	CleanExpiredTokens(ctx context.Context, tokenType types.TokenType) error
}

type AuditLogRepository interface {
	SaveAuditLog(ctx context.Context, log *types.AuditLog) error
	GetAuditLogs(ctx context.Context, filter Filter) ([]*types.AuditLog, int64, error)
	GetAuditLogByID(ctx context.Context, id string) (*types.AuditLog, error)
	DeleteAuditLog(ctx context.Context, log *types.AuditLog) error
}

type RepositoryFactory interface {
	GetUserRepository() UserRepository
	GetTokenRepository() TokenRepository
}
