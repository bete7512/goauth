package types

import (
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/golang-jwt/jwt/v4"
)

type CustomJWTClaimsProvider interface {
	GetClaims(user models.User) (map[string]interface{}, error)
}

type TokenManagerInterface interface {
	GenerateAccessToken(user models.User, duration time.Duration, secretKey string) (string, error)
	HashPassword(password string) (string, error)
	ValidatePassword(hashedPassword, password string) error
	GenerateTokens(user *models.User) (accessToken string, refreshToken string, err error)
	ValidateToken(tokenString string) (jwt.MapClaims, error)
	GenerateRandomToken(length int) (string, error)
	GenerateBase64Token(length int) (string, error)
}

type EmailSender interface {
	SendVerification(user models.User, redirectUrl string) error
	SendPasswordReset(user models.User, redirectUrl string) error
	SendTwoFactorCode(user models.User, code string) error
	SendMagicLink(user models.User, redirectUrl string) error
}

type SMSSender interface {
	SendTwoFactorCode(user models.User, code string) error
}

// type UserRepository interface {
// 	CreateUser(user *models.User) error
// 	UpsertUserByEmail(user *models.User) error
// 	GetUserByEmail(email string) (*models.User, error)
// 	GetUserByID(id string) (*models.User, error)
// 	UpdateUser(user *models.User) error
// 	DeleteUser(user *models.User) error
// 	GetAllUsers(interfaces.Filter) ([]*models.User, int64, error)
// }

// type TokenRepository interface {
// 	SaveToken(userID, token string, tokenType models.TokenType, expiry time.Duration) error
// 	ValidateToken(token string, tokenType models.TokenType) (bool, *string, error)
// 	ValidateTokenWithUserID(userID, token string, tokenType models.TokenType) (bool, error)
// 	InvalidateToken(userID, token string, tokenType models.TokenType) error
// 	InvalidateAllTokens(userID string, tokenType models.TokenType) error
// }
// type RepositoryFactory interface {
// 	GetUserRepository() UserRepository
// 	GetTokenRepository() TokenRepository
// }
