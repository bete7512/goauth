package interfaces

import (
	"time"

	"github.com/bete7512/goauth/models"
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
	CreateUser(user *models.User) error
	UpsertUserByEmail(user *models.User) error
	GetUserByPhoneNumber(phoneNumber string) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
	GetUserByID(id string) (*models.User, error)
	UpdateUser(user *models.User) error
	DeleteUser(user *models.User) error
	GetAllUsers(Filter) ([]*models.User, int64, error)
}

type TokenRepository interface {
	SaveToken(userID, token string, tokenType models.TokenType, expiry time.Duration) error
	SaveTokenWithDeviceId(userID, token, deviceId string, tokenType models.TokenType, expiry time.Duration) error
	GetTokenByUserID(userID string, tokenType models.TokenType) (*models.Token, error)
	InvalidateToken(userID, token string, tokenType models.TokenType) error
	InvalidateAllTokens(userID string, tokenType models.TokenType) error
}

type AuditLogRepository interface {
	SaveAuditLog(log *models.AuditLog) error
	GetAuditLogs(filter Filter) ([]*models.AuditLog, int64, error)
	GetAuditLogByID(id string) (*models.AuditLog, error)
	DeleteAuditLog(log *models.AuditLog) error
}

type RepositoryFactory interface {
	GetUserRepository() UserRepository
	GetTokenRepository() TokenRepository
}
