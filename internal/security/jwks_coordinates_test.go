package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/require"
)

// An ES256 JWK must carry full-length coordinates (RFC 7518 section 6.2.1.2).
// Deriving them from big.Int dropped a leading zero byte for about one key in
// 128, and strict verifiers reject such keys. The derived key ID must stay
// what earlier releases computed, so tokens they signed still verify.
func TestES256JWKSUsesFullLengthCoordinatesAndStableKID(t *testing.T) {
	var priv *ecdsa.PrivateKey
	for i := 0; i < 20000 && priv == nil; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		point, err := k.PublicKey.Bytes()
		require.NoError(t, err)
		if point[1] == 0 {
			priv = k
		}
	}
	require.NotNil(t, priv, "expected to generate a key whose X coordinate starts with a zero byte")
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	sm := NewSecurityManager(types.SecurityConfig{
		JwtSecretKey:     "this-is-a-32-character-secret-ok",
		EncryptionKey:    "encryption-key-at-least-16",
		Session:          types.SessionConfig{AccessTokenTTL: time.Hour},
		JWTAlgorithm:     types.JWTAlgorithmES256,
		JWTPrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	})
	require.NoError(t, sm.JWTKeyringError())
	jwks := sm.JWKS()
	require.Len(t, jwks.Keys, 1)
	key := jwks.Keys[0]

	point, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	x, err := base64.RawURLEncoding.DecodeString(key.X)
	require.NoError(t, err)
	y, err := base64.RawURLEncoding.DecodeString(key.Y)
	require.NoError(t, err)
	require.Len(t, x, 32, "x must keep its leading zero byte")
	require.Len(t, y, 32)
	require.Equal(t, point[1:33], x)
	require.Equal(t, point[33:], y)

	legacy := sha256.New()
	legacy.Write(new(big.Int).SetBytes(point[1:33]).Bytes())
	legacy.Write(new(big.Int).SetBytes(point[33:]).Bytes())
	require.Equal(t, base64.RawURLEncoding.EncodeToString(legacy.Sum(nil)[:8]), key.Kid, "derived key ID must not change")

	access, _, err := sm.GenerateTokens(testUser(), nil)
	require.NoError(t, err)
	_, err = sm.ValidateJWTToken(access)
	require.NoError(t, err)
}
