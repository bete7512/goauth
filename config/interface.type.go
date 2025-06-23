package config

import (
	"context"
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
	ValidateJWTToken(tokenString string) (jwt.MapClaims, error)
	GenerateRandomToken(length int) (string, error)
	GenerateNumericOTP(length int) (string, error)
	HashToken(token string) (string, error)
	ValidateHashedToken(hashedToken, token string) error
	GenerateBase64Token(length int) (string, error)
}

type RateLimiter interface {
	Allow(key string, config LimiterConfig) bool
	Close() error
}
type CaptchaVerifier interface {
	Verify(ctx context.Context, token string, remoteIP string) (bool, error)
}
