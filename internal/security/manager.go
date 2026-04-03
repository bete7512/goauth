package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

// HashRefreshToken produces a hex-encoded SHA-256 hash of a refresh token.
// SHA-256 is appropriate here because refresh tokens have high entropy (unlike
// passwords), so brute-force attacks are infeasible even without a slow hash.
func (t *SecurityManager) HashRefreshToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// HashRefreshToken is a package-level convenience for SHA-256 hashing of refresh tokens.
func HashRefreshToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Encrypt encrypts plaintext using AES-256-GCM. The encryption key is derived
// from Config.EncryptionKey via SHA-256 to ensure a 32-byte key.
// Output format: base64(nonce || ciphertext).
func (t *SecurityManager) Encrypt(data string) (string, error) {
	if t.Config.EncryptionKey == "" {
		return "", fmt.Errorf("encryption key not configured")
	}

	key := deriveKey(t.Config.EncryptionKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data produced by Encrypt using AES-256-GCM.
func (t *SecurityManager) Decrypt(data string) (string, error) {
	if t.Config.EncryptionKey == "" {
		return "", fmt.Errorf("encryption key not configured")
	}

	key := deriveKey(t.Config.EncryptionKey)

	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// deriveKey produces a 32-byte AES-256 key from an arbitrary-length passphrase
// using SHA-256.
func deriveKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
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
