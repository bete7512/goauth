package interfaces

import (
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v4"
)

type TokenManagerInterface interface {
	GenerateAccessToken(user types.User, duration time.Duration, secretKey string) (string, error)
	HashPassword(password string) (string, error)
	ValidatePassword(hashedPassword, password string) error
	GenerateTokens(user *types.User) (accessToken string, refreshToken string, err error)
	ValidateJWTToken(tokenString string) (jwt.MapClaims, error)
	GenerateRandomToken(length int) (string, error)
	GenerateNumericOTP(length int) (string, error)
	HashToken(token string) (string, error)
	ValidateHashedToken(hashedToken, token string) error
	GenerateBase64Token(length int) (string, error)
}
