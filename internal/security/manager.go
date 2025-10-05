package security

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type SecurityManager struct {
	Config config.Config
}

func NewSecurityManager(config config.Config) *SecurityManager {
	return &SecurityManager{Config: config}
}

func (t *SecurityManager) GenerateAccessToken(user models.User, duration time.Duration, secretKey string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(duration).Unix(),
	}
	if t.Config.Security.CustomClaimsProvider != nil {
		customClaims, err := t.Config.Security.CustomClaimsProvider.GetClaims(user)
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
func (t *SecurityManager) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), t.Config.Security.HashSaltLength)
	return string(bytes), err
}

// ValidatePassword checks if the provided password is correct
func (t *SecurityManager) ValidatePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateTokens creates a new JWT access token and refresh token
func (t *SecurityManager) GenerateTokens(user *models.User) (accessToken string, refreshToken string, err error) {
	// Create access token
	if user == nil {
		return "", "", errors.New("user is nil")
	}
	accessTokenClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(t.Config.Security.AccessTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
		"type":    "access",
	}
	if t.Config.Security.CustomClaimsProvider != nil {
		customClaims, err := t.Config.Security.CustomClaimsProvider.GetClaims(*user)
		if err != nil {
			return "", "", err
		}
		for k, v := range customClaims {
			accessTokenClaims[k] = v
		}
	}
	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessToken, err = accessTokenObj.SignedString([]byte(t.Config.Security.JwtSecretKey))
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
func (t *SecurityManager) ValidateJWTToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(t.Config.Security.JwtSecretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New("token expired")
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, errors.New("token not valid yet")
		}
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (t *SecurityManager) GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (t *SecurityManager) GenerateNumericOTP(length int) (string, error) {
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

func (t *SecurityManager) GenerateBase64Token(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (t *SecurityManager) HashToken(token string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), t.Config.Security.HashSaltLength)
	return string(hashedToken), err
}

func (t *SecurityManager) ValidateHashedToken(hashedToken, token string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(token))
}

func (t *SecurityManager) Encrypt(data string) (string, error) {
	// do some research on how to encrypt and encrypt data in better way
	//TODO: encryptedData, err := t.Config.Security.EncryptionKey.Encrypt([]byte(data))
	return data, nil
}

func (t *SecurityManager) Decrypt(data string) (string, error) {
	//TODO: decryptedData, err := t.Config.Security.EncryptionKey.Decrypt([]byte(data))
	return data, nil
}
