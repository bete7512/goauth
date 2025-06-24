package tokenManager

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type TokenManager struct {
	Config config.Config
}

func NewTokenManager(config config.Config) *TokenManager {
	return &TokenManager{Config: config}
}

func (t *TokenManager) GenerateAccessToken(user types.User, duration time.Duration, secretKey string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(duration).Unix(),
	}
	if t.Config.Features.EnableCustomJWT && t.Config.AuthConfig.JWT.ClaimsProvider != nil {
		customClaims, err := t.Config.AuthConfig.JWT.ClaimsProvider.GetClaims(user)
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
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), t.Config.AuthConfig.PasswordPolicy.HashSaltLength)
	return string(bytes), err
}

// ValidatePassword checks if the provided password is correct
func (t *TokenManager) ValidatePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateTokens creates a new JWT access token and refresh token
func (t *TokenManager) GenerateTokens(user *types.User) (accessToken string, refreshToken string, err error) {
	// Create access token
	if user == nil {
		return "", "", errors.New("user is nil")
	}
	accessTokenClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(t.Config.AuthConfig.JWT.AccessTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
		"type":    "access",
	}
	if t.Config.Features.EnableCustomJWT && t.Config.AuthConfig.JWT.ClaimsProvider != nil {
		customClaims, err := t.Config.AuthConfig.JWT.ClaimsProvider.GetClaims(*user)
		if err != nil {
			return "", "", err
		}
		for k, v := range customClaims {
			accessTokenClaims[k] = v
		}
	}
	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessToken, err = accessTokenObj.SignedString([]byte(t.Config.AuthConfig.JWT.Secret))
	if err != nil {
		return "", "", err
	}
	refreshToken, err = t.GenerateRandomToken(32)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// ValidateToken validates a JWT token
func (t *TokenManager) ValidateJWTToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(t.Config.AuthConfig.JWT.Secret), nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, errors.New("token_expired")
			}
			if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, errors.New("token not valid yet")
			}
		}
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

func (t *TokenManager) GenerateNumericOTP(length int) (string, error) {
	digits := "0123456789"
	token := make([]byte, length)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	for i := range token {
		token[i] = digits[int(token[i])%10]
	}
	return string(token), nil
}

func (t *TokenManager) GenerateBase64Token(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (t *TokenManager) HashToken(token string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), t.Config.AuthConfig.Tokens.HashSaltLength)
	return string(hashedToken), err
}

func (t *TokenManager) ValidateHashedToken(hashedToken, token string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(token))
}
