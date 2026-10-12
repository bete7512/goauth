package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Compile-time check: SecurityManager must satisfy types.SecurityManager
var _ types.SecurityManager = (*SecurityManager)(nil)

type SecurityManager struct {
	Config     types.SecurityConfig
	keyring    *jwtKeyring
	keyringErr error
	retained   map[string]retainedJWTKey
}

// JWTKeyringError returns the key-loading error captured during NewSecurityManager,
// if the configured JWT algorithm required asymmetric keys and loading failed.
// Returns nil on success.
func (t *SecurityManager) JWTKeyringError() error {
	return t.keyringErr
}

// JWKS returns the public JSON Web Key Set. Empty for HS256.
func (t *SecurityManager) JWKS() types.JWKS {
	if t.keyring == nil {
		return types.JWKS{Keys: []types.JWK{}}
	}
	keys := t.keyring.jwks()
	for _, key := range t.retained {
		if time.Now().Before(key.notAfter) {
			keys.Keys = append(keys.Keys, key.key.jwks().Keys...)
		}
	}
	return keys
}

// JWTAlgorithm reports the active signing algorithm.
func (t *SecurityManager) JWTAlgorithm() types.JWTAlgorithm {
	if t.keyring == nil {
		return t.Config.JWTAlgorithm
	}
	return t.keyring.algorithm
}

// NewSecurityManager builds a SecurityManager from the provided config.
// For asymmetric JWT algorithms the key material is loaded eagerly so
// misconfiguration is surfaced at startup rather than on first token issue.
// A key-loading failure disables signing and verification. Auth.New checks
// JWTKeyringError before activating any modules.
func NewSecurityManager(config types.SecurityConfig) *SecurityManager {
	if config.JWTIssuer == "" {
		config.JWTIssuer = "goauth"
	}
	if config.JWTAudience == "" {
		config.JWTAudience = "goauth"
	}
	kr, err := newJWTKeyring(config)
	var retained map[string]retainedJWTKey
	if err == nil {
		retained, err = loadRetainedKeys(kr, config.RetainedJWTKeys)
	}
	if err != nil {
		kr = nil
	}
	return &SecurityManager{Config: config, keyring: kr, keyringErr: err, retained: retained}
}

func (t *SecurityManager) GenerateAccessToken(user models.User, claims map[string]interface{}) (string, error) {
	claimsMap := jwt.MapClaims{
		"user_id":       user.ID,
		"sub":           user.ID,
		"type":          "access",
		"iss":           t.Config.JWTIssuer,
		"aud":           t.Config.JWTAudience,
		"iat":           time.Now().Unix(),
		"token_version": user.TokenVersion,
		"exp":           time.Now().Add(t.Config.Session.AccessTokenTTL).Unix(),
	}
	if t.Config.CustomClaimsProvider != nil {
		customClaims, err := t.Config.CustomClaimsProvider.GetClaims(&user)
		if err != nil {
			return "", err
		}
		for k, v := range customClaims {
			if IsReservedClaim(k) {
				return "", fmt.Errorf("reserved custom claim: %s", k)
			}
			claimsMap[k] = v
		}
	}
	for k, v := range claims {
		if reservedClaim(k) {
			return "", fmt.Errorf("reserved claim: %s", k)
		}
		claimsMap[k] = v
	}

	return t.signJWT(claimsMap)
}

// HashPassword creates a bcrypt hash of the password
func (t *SecurityManager) HashPassword(password string) (string, error) {
	if err := t.Config.PasswordPolicy.Validate(password); err != nil {
		return "", err
	}
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
	accessToken, err = t.GenerateAccessToken(*user, claims)
	if err != nil {
		return "", "", err
	}
	refreshToken, err = t.GenerateRandomToken(32)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// signJWT signs the given claims using the configured keyring (HS256/RS256/ES256)
// and stamps the "kid" header when one is configured.
func (t *SecurityManager) signJWT(claims jwt.MapClaims) (string, error) {
	if t.keyring == nil {
		return "", errors.New("security manager: keyring not initialized")
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	if len(encoded) > 4096 {
		return "", fmt.Errorf("JWT claims exceed 4096 bytes")
	}
	token := jwt.NewWithClaims(t.keyring.method, claims)
	t.keyring.applyHeader(token)
	return token.SignedString(t.keyring.signKey())
}

// ValidateJWTToken validates a JWT token and returns its claims as a plain map.
// The expected signing method is enforced to match the configured algorithm —
// this rejects "alg: none" and algorithm-confusion attacks.
func (t *SecurityManager) ValidateJWTToken(tokenString string) (map[string]interface{}, error) {
	if t.keyring == nil {
		return nil, errors.New("security manager: keyring not initialized")
	}
	allowed := []string{t.keyring.method.Alg()}
	for _, key := range t.retained {
		allowed = append(allowed, key.key.method.Alg())
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		key := t.keyring
		if kid != key.kid {
			retained, ok := t.retained[kid]
			if !ok || !time.Now().Before(retained.notAfter) {
				return nil, fmt.Errorf("unknown or retired JWT key")
			}
			key = retained.key
		}
		if token.Method.Alg() != key.method.Alg() {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key.verifyKey(), nil
	}, jwt.WithValidMethods(allowed), jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(), jwt.WithIssuer(t.Config.JWTIssuer), jwt.WithAudience(t.Config.JWTAudience))

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
// Output format: v1.base64url(key ID).base64(nonce || ciphertext).
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

	kid := t.Config.EncryptionKeyID
	if kid == "" {
		kid = "default"
	}
	header := "v1." + base64.RawURLEncoding.EncodeToString([]byte(kid)) + "."
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), []byte(header))
	return header + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data produced by Encrypt using AES-256-GCM.
func (t *SecurityManager) Decrypt(data string) (string, error) {
	if t.Config.EncryptionKey == "" {
		return "", fmt.Errorf("encryption key not configured")
	}

	secret := t.Config.EncryptionKey
	var aad []byte
	if strings.HasPrefix(data, "v1.") {
		parts := strings.SplitN(data, ".", 3)
		if len(parts) != 3 {
			return "", fmt.Errorf("invalid encrypted envelope")
		}
		rawID, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("invalid encryption key ID")
		}
		kid := string(rawID)
		active := t.Config.EncryptionKeyID
		if active == "" {
			active = "default"
		}
		if kid != active {
			var ok bool
			secret, ok = t.Config.DecryptionKeys[kid]
			if !ok {
				return "", fmt.Errorf("unknown encryption key")
			}
		}
		aad = []byte(parts[0] + "." + parts[1] + ".")
		data = parts[2]
	}
	key := deriveKey(secret)

	raw, err := base64.StdEncoding.Strict().DecodeString(data)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
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
		"user_id":       user.ID,
		"sub":           user.ID,
		"iss":           t.Config.JWTIssuer,
		"aud":           t.Config.JWTAudience,
		"token_version": user.TokenVersion,
		"type":          "refresh",
		"jti":           jti,
		"exp":           time.Now().Add(t.Config.Session.RefreshTokenTTL).Unix(),
		"iat":           time.Now().Unix(),
	}

	tokenString, err := t.signJWT(claims)
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

// GenerateChallengeToken signs a continuation, never an access credential.
func (t *SecurityManager) GenerateChallengeToken(userID, nonce string, ttl time.Duration) (string, error) {
	return t.signJWT(jwt.MapClaims{"user_id": userID, "sub": userID, "iss": t.Config.JWTIssuer, "aud": t.Config.JWTAudience, "type": "2fa_pending", "jti": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(ttl).Unix()})
}
