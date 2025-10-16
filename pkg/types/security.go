package types

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/golang-jwt/jwt/v5"
)

type SessionConfig struct {
	Name            string
	SessionTTL      time.Duration
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Secure          bool
	HttpOnly        bool
	SameSite        http.SameSite
	Domain          string
	Path            string
	MaxAge          int
}

type SecurityConfig struct {
	JwtSecretKey         string
	EncryptionKey        string
	HashSaltLength       int
	CustomClaimsProvider CustomClaimsProvider
	Session              SessionConfig
	PasswordPolicy       PasswordPolicy
}

type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSpecial   bool
}

type CustomClaimsProvider interface {
	GetClaims(user *models.User) (jwt.MapClaims, error)
}
