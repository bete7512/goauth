package types

import "github.com/bete7512/goauth/pkg/models"

// SecurityManager exposes cryptographic and token utilities to module authors.
// An implementation is created from config.Config.Security and injected into
// config.ModuleDependencies.SecurityManager during auth.Initialize().
type SecurityManager interface {
	// Password hashing / verification
	HashPassword(password string) (string, error)
	ValidatePassword(hashedPassword, password string) error

	// JWT token generation
	GenerateAccessToken(user models.User, claims map[string]interface{}) (string, error)
	GenerateTokens(user *models.User, claims map[string]interface{}) (string, string, error)
	GenerateStatelessRefreshToken(user *models.User) (string, string, error)

	// JWT token validation — returns map[string]interface{} (e.g. {"user_id": "...", "exp": ...})
	ValidateJWTToken(tokenString string) (map[string]interface{}, error)

	// Opaque token generation
	GenerateRandomToken(length int) (string, error)   // hex-encoded
	GenerateNumericOTP(length int) (string, error)    // digit string
	GenerateBase64Token(length int) (string, error)   // base64url

	// Opaque token hashing / verification (bcrypt)
	HashToken(token string) (string, error)
	ValidateHashedToken(hashedToken, token string) error

	// Symmetric encryption (stub — implement before relying on this)
	Encrypt(data string) (string, error)
	Decrypt(data string) (string, error)
}
