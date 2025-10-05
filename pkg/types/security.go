package types

import (
	"time"

	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/golang-jwt/jwt/v5"
)

type CookieConfig struct {
	Name string
}
type SecurityConfig struct {
	JwtSecretKey         string
	SessionDuration      time.Duration
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	EncryptionKey        string
	HashSaltLength       int
	CustomClaimsProvider CustomClaimsProvider
	Cookie               CookieConfig
}

type CustomClaimsProvider interface {
	GetClaims(user models.User) (jwt.MapClaims, error)
}
