package tokenManager

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/types"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type TokenManager struct {
	Config types.Config
}

func NewTokenManager(config types.Config) *TokenManager {
	return &TokenManager{Config: config}
}

func (t *TokenManager) GenerateAccessToken(user models.User, duration time.Duration, secretKey string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(duration).Unix(),
	}

	if t.Config.AuthConfig.EnableAddCustomJWTClaims && t.Config.CustomJWTClaimsProvider != nil {
		customClaims, err := t.Config.CustomJWTClaimsProvider.GetClaims(user)
		if err != nil {
			return "", err
		}
		for k, v := range customClaims {
			claims[k] = v
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

// HashPassword creates a bcrypt hash of the password
func (t *TokenManager) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), t.Config.PasswordPolicy.HashSaltLength)
	return string(bytes), err
}

// ValidatePassword checks if the provided password is correct
func (t *TokenManager) ValidatePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateTokens creates a new JWT access token and refresh token
func (t *TokenManager) GenerateTokens(user *models.User) (accessToken string, refreshToken string, err error) {
	// Create access token
	if user == nil {
		return "", "", errors.New("user is nil")
	}
	accessTokenClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(t.Config.AuthConfig.Cookie.AccessTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
		"type":    "access",
	}
	if t.Config.AuthConfig.EnableAddCustomJWTClaims && t.Config.CustomJWTClaimsProvider != nil {
		customClaims, err := t.Config.CustomJWTClaimsProvider.GetClaims(*user)
		if err != nil {
			return "", "", err
		}
		for k, v := range customClaims {
			accessTokenClaims[k] = v
		}
	}
	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessToken, err = accessTokenObj.SignedString([]byte(t.Config.AuthConfig.JWTSecret))
	if err != nil {
		return "", "", err
	}
	// Create refresh token
	refreshTokenClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(t.Config.AuthConfig.Cookie.RefreshTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
		"type":    "refresh",
	}
	refreshTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshToken, err = refreshTokenObj.SignedString([]byte(t.Config.AuthConfig.JWTSecret))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// ValidateToken validates a JWT token
func (t *TokenManager) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(t.Config.AuthConfig.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (t *TokenManager) GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (t *TokenManager) GenerateBase64Token(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
