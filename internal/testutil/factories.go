package testutil

import (
	"time"

	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// TestUser creates a user with sensible defaults. Override fields as needed.
func TestUser() *models.User {
	now := time.Now()
	return &models.User{
		ID:            uuid.New().String(),
		Email:         "test@example.com",
		Username:      "testuser",
		Name:          "Test User",
		PasswordHash:  HashPassword("password123"),
		Active:        true,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     &now,
	}
}

// TestSession creates a session with sensible defaults.
func TestSession(userID string) *models.Session {
	now := time.Now()
	return &models.Session{
		ID:                    uuid.New().String(),
		UserID:                userID,
		RefreshToken:          uuid.New().String(),
		RefreshTokenExpiresAt: now.Add(7 * 24 * time.Hour),
		ExpiresAt:             now.Add(30 * 24 * time.Hour),
		UserAgent:             "TestAgent/1.0",
		IPAddress:             "127.0.0.1",
		CreatedAt:             now,
		UpdatedAt:             now,
	}
}

// TestToken creates a token with sensible defaults.
func TestToken(userID, tokenType string) *models.Token {
	return &models.Token{
		ID:        uuid.New().String(),
		UserID:    userID,
		Type:      tokenType,
		Token:     uuid.New().String(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}
}

// TestExpiredToken creates an expired token.
func TestExpiredToken(userID, tokenType string) *models.Token {
	t := TestToken(userID, tokenType)
	t.ExpiresAt = time.Now().Add(-1 * time.Hour)
	return t
}

// TestVerificationToken creates a token with Code/Email fields for verification tests.
func TestVerificationToken(userID, tokenType string) *models.Token {
	t := TestToken(userID, tokenType)
	t.Code = "123456"
	t.Email = "test@example.com"
	return t
}

// TestExpiredVerificationToken creates an expired token with verification fields.
func TestExpiredVerificationToken(userID, tokenType string) *models.Token {
	t := TestVerificationToken(userID, tokenType)
	t.ExpiresAt = time.Now().Add(-1 * time.Hour)
	return t
}

// HashPassword hashes a plaintext password for test fixtures.
func HashPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return string(hash)
}

// TestSecurityManager returns a SecurityManager configured for tests.
func TestSecurityManager() *security.SecurityManager {
	return security.NewSecurityManager(types.SecurityConfig{
		JwtSecretKey:  "test-secret-key-for-unit-tests",
		EncryptionKey: "test-encryption-key-for-tests!",
		Session: types.SessionConfig{
			Name:            "test_session",
			SessionTTL:      30 * 24 * time.Hour,
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
		},
		PasswordPolicy: types.PasswordPolicy{
			MinLength:        4,
			MaxLength:        64,
			RequireUppercase: false,
			RequireSpecial:   false,
		},
	})
}

// TestCoreConfig returns a CoreConfig for tests.
func TestCoreConfig() *config.CoreConfig {
	return &config.CoreConfig{
		RequireEmailVerification: false,
		RequirePhoneVerification: false,
		RequireUserName:          false,
		RequirePhoneNumber:       false,
		UniquePhoneNumber:        true,
	}
}

// TestSessionModuleConfig returns a SessionModuleConfig for tests.
func TestSessionModuleConfig() *config.SessionModuleConfig {
	return &config.SessionModuleConfig{
		EnableSessionManagement: true,
	}
}

// TestConfig returns a full Config for tests.
func TestConfig() *config.Config {
	return &config.Config{
		AutoMigrate: false,
		BasePath:    "/api/v1",
		Security: types.SecurityConfig{
			JwtSecretKey:  "test-secret-key-for-unit-tests",
			EncryptionKey: "test-encryption-key-for-tests!",
			Session: types.SessionConfig{
				Name:            "test_session",
				SessionTTL:      30 * 24 * time.Hour,
				AccessTokenTTL:  15 * time.Minute,
				RefreshTokenTTL: 7 * 24 * time.Hour,
			},
			PasswordPolicy: types.PasswordPolicy{
				MinLength: 4,
				MaxLength: 64,
			},
		},
		Core: &config.CoreConfig{
			RequireEmailVerification: false,
			RequirePhoneVerification: false,
			RequireUserName:          false,
			UniquePhoneNumber:        true,
		},
	}
}

// GenerateTempToken generates a valid 2FA temp token for testing
func GenerateTempToken(userID string) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    "2fa_pending",
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret-key-for-unit-tests"))
	return tokenString
}

// GenerateExpiredTempToken generates an expired 2FA temp token for testing
func GenerateExpiredTempToken(userID string, expiryOffset time.Duration) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    "2fa_pending",
		"exp":     time.Now().Add(expiryOffset).Unix(), // expiryOffset should be negative for expired tokens
		"iat":     time.Now().Add(expiryOffset - time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret-key-for-unit-tests"))
	return tokenString
}
