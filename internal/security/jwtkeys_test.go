package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateRSAPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
}

func generateECPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func testUser() *models.User {
	return &models.User{ID: "user-123", Email: "u@example.com"}
}

func TestSecurityManager_HS256_DefaultAlgorithm(t *testing.T) {
	sm := NewSecurityManager(types.SecurityConfig{
		JwtSecretKey:  "this-is-a-32-character-secret-ok",
		EncryptionKey: "encryption-key-at-least-16",
		Session:       types.SessionConfig{AccessTokenTTL: time.Hour},
	})

	assert.Equal(t, types.JWTAlgorithmHS256, sm.JWTAlgorithm())
	assert.NoError(t, sm.JWTKeyringError())
	assert.Empty(t, sm.JWKS().Keys, "HS256 must not expose keys in JWKS")

	access, _, err := sm.GenerateTokens(testUser(), nil)
	require.NoError(t, err)
	require.NotEmpty(t, access)

	claims, err := sm.ValidateJWTToken(access)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims["user_id"])
}

func TestSecurityManager_RS256_SignAndVerifyAndJWKS(t *testing.T) {
	privPEM := generateRSAPEM(t)

	sm := NewSecurityManager(types.SecurityConfig{
		JwtSecretKey:     "this-is-a-32-character-secret-ok",
		EncryptionKey:    "encryption-key-at-least-16",
		Session:          types.SessionConfig{AccessTokenTTL: time.Hour},
		JWTAlgorithm:     types.JWTAlgorithmRS256,
		JWTPrivateKeyPEM: privPEM,
	})

	require.NoError(t, sm.JWTKeyringError())
	assert.Equal(t, types.JWTAlgorithmRS256, sm.JWTAlgorithm())

	jwks := sm.JWKS()
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "RSA", jwks.Keys[0].Kty)
	assert.Equal(t, "RS256", jwks.Keys[0].Alg)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
	assert.NotEmpty(t, jwks.Keys[0].Kid)
	assert.NotEmpty(t, jwks.Keys[0].N)
	assert.NotEmpty(t, jwks.Keys[0].E)

	access, _, err := sm.GenerateTokens(testUser(), nil)
	require.NoError(t, err)

	claims, err := sm.ValidateJWTToken(access)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims["user_id"])
}

func TestSecurityManager_ES256_SignAndVerifyAndJWKS(t *testing.T) {
	privPEM := generateECPEM(t)

	sm := NewSecurityManager(types.SecurityConfig{
		JwtSecretKey:     "this-is-a-32-character-secret-ok",
		EncryptionKey:    "encryption-key-at-least-16",
		Session:          types.SessionConfig{AccessTokenTTL: time.Hour},
		JWTAlgorithm:     types.JWTAlgorithmES256,
		JWTPrivateKeyPEM: privPEM,
	})

	require.NoError(t, sm.JWTKeyringError())
	assert.Equal(t, types.JWTAlgorithmES256, sm.JWTAlgorithm())

	jwks := sm.JWKS()
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "EC", jwks.Keys[0].Kty)
	assert.Equal(t, "ES256", jwks.Keys[0].Alg)
	assert.Equal(t, "P-256", jwks.Keys[0].Crv)
	assert.NotEmpty(t, jwks.Keys[0].X)
	assert.NotEmpty(t, jwks.Keys[0].Y)

	access, _, err := sm.GenerateTokens(testUser(), nil)
	require.NoError(t, err)

	claims, err := sm.ValidateJWTToken(access)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims["user_id"])
}

func TestSecurityManager_RS256_MissingKey_RecordsError(t *testing.T) {
	sm := NewSecurityManager(types.SecurityConfig{
		JwtSecretKey:  "this-is-a-32-character-secret-ok",
		EncryptionKey: "encryption-key-at-least-16",
		Session:       types.SessionConfig{AccessTokenTTL: time.Hour},
		JWTAlgorithm:  types.JWTAlgorithmRS256,
		// No PEM key: construction records an error and disables crypto operations.
	})

	require.Error(t, sm.JWTKeyringError())
	assert.Equal(t, types.JWTAlgorithmRS256, sm.JWTAlgorithm())
	_, _, err := sm.GenerateTokens(testUser(), nil)
	require.Error(t, err, "invalid key material must not enable a fallback signer")
}

func TestSecurityManager_RejectsAlgorithmConfusion(t *testing.T) {
	// Sign with HS256 using the public-key material as the "secret" — a classic
	// algorithm-confusion attack. ValidateJWTToken must refuse because it
	// compares the parsed alg against the configured alg.
	sm := NewSecurityManager(types.SecurityConfig{
		JwtSecretKey:     "this-is-a-32-character-secret-ok",
		EncryptionKey:    "encryption-key-at-least-16",
		Session:          types.SessionConfig{AccessTokenTTL: time.Hour},
		JWTAlgorithm:     types.JWTAlgorithmRS256,
		JWTPrivateKeyPEM: generateRSAPEM(t),
	})
	require.NoError(t, sm.JWTKeyringError())

	hs := NewSecurityManager(types.SecurityConfig{
		JwtSecretKey:  "this-is-a-32-character-secret-ok",
		EncryptionKey: "encryption-key-at-least-16",
		Session:       types.SessionConfig{AccessTokenTTL: time.Hour},
	})
	hsToken, _, err := hs.GenerateTokens(testUser(), nil)
	require.NoError(t, err)

	_, err = sm.ValidateJWTToken(hsToken)
	assert.Error(t, err, "RS256 verifier must reject HS256-signed tokens")
}
