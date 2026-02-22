package security

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Compile-time check: SecurityManager must satisfy types.SecurityManager
var _ types.SecurityManager = (*SecurityManager)(nil)

type SecurityManager struct {
	Config types.SecurityConfig
}

func NewSecurityManager(config types.SecurityConfig) *SecurityManager {
	return &SecurityManager{Config: config}
}

func (t *SecurityManager) GenerateAccessToken(user models.User, claims map[string]interface{}) (string, error) {
	claimsMap := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(t.Config.Session.AccessTokenTTL).Unix(),
	}
	if t.Config.CustomClaimsProvider != nil {
		customClaims, err := t.Config.CustomClaimsProvider.GetClaims(&user)
		if err != nil {
			return "", err
		}
		for k, v := range customClaims {
			claimsMap[k] = v
		}
	}
	for k, v := range claims {
		claimsMap[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsMap)
	return token.SignedString([]byte(t.Config.JwtSecretKey))
}

// HashPassword creates a bcrypt hash of the password
func (t *SecurityManager) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), t.Config.HashSaltLength)
	return string(bytes), err
}

// ValidatePassword checks if the provided password is correct
func (t *SecurityManager) ValidatePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateTokens creates a new JWT access token and refresh token
func (t *SecurityManager) GenerateTokens(user *models.User, claims map[string]interface{}) (accessToken string, refreshToken string, err error) {
	// Create access token
	if user == nil {
		return "", "", errors.New("user is nil")
	}
	accessTokenClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(t.Config.Session.AccessTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
		"type":    "access",
	}
	for k, v := range claims {
		accessTokenClaims[k] = v
	}
	if t.Config.CustomClaimsProvider != nil {
		customClaims, err := t.Config.CustomClaimsProvider.GetClaims(user)
		if err != nil {
			return "", "", err
		}
		for k, v := range customClaims {
			accessTokenClaims[k] = v
		}
	}
	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessToken, err = accessTokenObj.SignedString([]byte(t.Config.JwtSecretKey))
	if err != nil {
		return "", "", err
	}
	refreshToken, err = t.GenerateRandomToken(32)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// ValidateJWTToken validates a JWT token and returns its claims as a plain map.
func (t *SecurityManager) ValidateJWTToken(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(t.Config.JwtSecretKey), nil
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
		return map[string]interface{}(claims), nil
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
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), t.Config.HashSaltLength)
	return string(hashedToken), err
}

func (t *SecurityManager) ValidateHashedToken(hashedToken, token string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(token))
}

func (t *SecurityManager) Encrypt(data string) (string, error) {
	// do some research on how to encrypt and encrypt data in better way
	//TODO: encryptedData, err := t.Config.EncryptionKey.Encrypt([]byte(data))
	return data, nil
}

func (t *SecurityManager) Decrypt(data string) (string, error) {
	//TODO: decryptedData, err := t.Config.Security.EncryptionKey.Decrypt([]byte(data))
	return data, nil
}

// GenerateStatelessRefreshToken generates a JWT refresh token with a random JTI
func (t *SecurityManager) GenerateStatelessRefreshToken(user *models.User) (string, string, error) {
	// Generate JTI (nonce)
	jti, err := t.GenerateRandomToken(32)
	if err != nil {
		return "", "", err
	}

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"type":    "refresh",
		"jti":     jti,
		"exp":     time.Now().Add(t.Config.Session.RefreshTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(t.Config.JwtSecretKey))
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}
