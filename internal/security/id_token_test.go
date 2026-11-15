package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func idTokenClaims() map[string]interface{} {
	return map[string]interface{}{
		"iss": "https://app.example.com/oidc", "sub": "user-1", "aud": "client-1",
		"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
	}
}

func TestSignIDTokenCarriesJWTTypeAndKeyID(t *testing.T) {
	signer, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: rsaPEM(t)})
	require.NoError(t, err)

	raw, err := signer.SignIDToken(idTokenClaims())
	require.NoError(t, err)

	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	require.NoError(t, err)
	require.Equal(t, "JWT", parsed.Header["typ"])
	require.Equal(t, "RS256", parsed.Header["alg"])
	require.Equal(t, signer.KeyID(), parsed.Header["kid"])

	claims, err := signer.Verify("JWT", raw)
	require.NoError(t, err)
	require.Equal(t, "user-1", claims["sub"])
}

func TestSignIDTokenRejectsOversizedClaims(t *testing.T) {
	signer, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: rsaPEM(t)})
	require.NoError(t, err)
	claims := idTokenClaims()
	claims["groups"] = strings.Repeat("x", maxTypedClaimsBytes)
	_, err = signer.SignIDToken(claims)
	require.ErrorContains(t, err, "exceed")
}

// An ID token signed with a key of its own never passes first-party
// validation, even when it copies the first-party issuer, audience and
// purpose claims.
func TestIDTokenFromDedicatedKeyIsNotAFirstPartyToken(t *testing.T) {
	manager := NewSecurityManager(types.SecurityConfig{
		JwtSecretKey: "01234567890123456789012345678901", JWTAlgorithm: types.JWTAlgorithmRS256, JWTPrivateKeyPEM: rsaPEM(t),
		Session: types.SessionConfig{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour},
	})
	require.NoError(t, manager.JWTKeyringError())
	dedicated, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: rsaPEM(t)})
	require.NoError(t, err)

	forged, err := dedicated.SignIDToken(map[string]interface{}{
		"iss": "goauth", "aud": "goauth", "type": "access", "user_id": "user-1", "sub": "user-1", "token_version": 0,
		"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
	})
	require.NoError(t, err)
	_, err = manager.ValidateJWTToken(forged)
	require.Error(t, err)
	_, err = ValidateCredential(manager, forged, "access")
	require.Error(t, err)
}

func TestSharesKeyWith(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	first, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: keyPEM})
	require.NoError(t, err)
	same, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: keyPEM, JWTKeyID: "another-name"})
	require.NoError(t, err)
	other, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: rsaPEM(t)})
	require.NoError(t, err)
	// The key lives on in other's key set as a retired key.
	retiring, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: rsaPEM(t), JWTKeyID: "new", RetainedJWTKeys: []types.JWTVerificationKey{{
		ID: "old", Algorithm: types.JWTAlgorithmRS256, PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), NotAfter: time.Now().Add(time.Hour),
	}}})
	require.NoError(t, err)

	require.True(t, first.SharesKeyWith(same), "the same key under another key ID is still the same key")
	require.False(t, first.SharesKeyWith(other))
	require.True(t, first.SharesKeyWith(retiring))
	require.False(t, first.SharesKeyWith(nil))
}
