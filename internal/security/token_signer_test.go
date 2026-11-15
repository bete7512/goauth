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
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func ecPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func rsaPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func accessClaims() map[string]interface{} {
	return map[string]interface{}{"iss": "https://as.example.com", "sub": "user-1", "aud": "https://mcp.example.com", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}
}

func TestTokenSignerInfersAlgorithmAndRoundTrips(t *testing.T) {
	for name, key := range map[string][]byte{"ES256": ecPEM(t), "RS256": rsaPEM(t)} {
		t.Run(name, func(t *testing.T) {
			signer, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: key})
			require.NoError(t, err)
			require.Equal(t, types.JWTAlgorithm(name), signer.Algorithm())
			require.NotEmpty(t, signer.KeyID())
			require.Len(t, signer.JWKS().Keys, 1)

			token, err := signer.Sign("at+jwt", accessClaims())
			require.NoError(t, err)
			parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
			require.NoError(t, err)
			require.Equal(t, "at+jwt", parsed.Header["typ"])
			require.Equal(t, signer.KeyID(), parsed.Header["kid"])

			claims, err := signer.Verify("at+jwt", token)
			require.NoError(t, err)
			require.Equal(t, "user-1", claims["sub"])
		})
	}
}

func TestTokenSignerRejectsWrongTypeExpiredAndForeignKeys(t *testing.T) {
	signer, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: ecPEM(t)})
	require.NoError(t, err)
	token, err := signer.Sign("at+jwt", accessClaims())
	require.NoError(t, err)

	_, err = signer.Verify("other+jwt", token)
	require.Error(t, err, "typ is part of the contract")

	expired := accessClaims()
	expired["exp"] = time.Now().Add(-time.Minute).Unix()
	stale, err := signer.Sign("at+jwt", expired)
	require.NoError(t, err)
	_, err = signer.Verify("at+jwt", stale)
	require.Error(t, err)

	noExpiry := accessClaims()
	delete(noExpiry, "exp")
	eternal, err := signer.Sign("at+jwt", noExpiry)
	require.NoError(t, err)
	_, err = signer.Verify("at+jwt", eternal)
	require.Error(t, err, "exp is required")

	other, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: ecPEM(t)})
	require.NoError(t, err)
	_, err = other.Verify("at+jwt", token)
	require.Error(t, err)

	_, err = signer.Sign("JWT", accessClaims())
	require.Error(t, err, "typed tokens must not look like first-party tokens")
	_, err = signer.Sign("", accessClaims())
	require.Error(t, err)
}

func TestTokenSignerRequiresAsymmetricKeys(t *testing.T) {
	_, err := NewTokenSigner(types.SecurityConfig{JWTAlgorithm: types.JWTAlgorithmHS256, JwtSecretKey: "01234567890123456789012345678901"})
	require.ErrorContains(t, err, "RS256 or ES256")
	_, err = NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: []byte("not a key")})
	require.Error(t, err)

	symmetric := NewSecurityManager(types.SecurityConfig{JwtSecretKey: "01234567890123456789012345678901"})
	_, err = symmetric.TokenSigner()
	require.ErrorContains(t, err, "symmetric")
}

// A typed token signed with the manager's own key must never pass first-party
// validation, and a first-party token must never pass typed verification.
func TestTypedAndFirstPartyTokensDoNotCross(t *testing.T) {
	manager := NewSecurityManager(types.SecurityConfig{
		JwtSecretKey: "01234567890123456789012345678901", JWTAlgorithm: types.JWTAlgorithmES256, JWTPrivateKeyPEM: ecPEM(t),
		Session: types.SessionConfig{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour},
	})
	require.NoError(t, manager.JWTKeyringError())
	signer, err := manager.TokenSigner()
	require.NoError(t, err)

	// Even with first-party issuer, audience and purpose claims copied in.
	forged, err := signer.Sign("at+jwt", map[string]interface{}{
		"iss": "goauth", "aud": "goauth", "type": "access", "user_id": "user-1", "sub": "user-1", "token_version": 0,
		"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
	})
	require.NoError(t, err)
	_, err = manager.ValidateJWTToken(forged)
	require.Error(t, err)
	_, err = ValidateCredential(manager, forged, "access")
	require.Error(t, err)

	firstParty, err := manager.GenerateAccessToken(models.User{ID: "user-1"}, nil)
	require.NoError(t, err)
	_, err = manager.ValidateJWTToken(firstParty)
	require.NoError(t, err)
	_, err = signer.Verify("at+jwt", firstParty)
	require.Error(t, err)
}

func TestTokenSignerRetainedKeys(t *testing.T) {
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	oldDER, err := x509.MarshalECPrivateKey(oldKey)
	require.NoError(t, err)
	oldPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: oldDER})
	oldPub, err := x509.MarshalPKIXPublicKey(&oldKey.PublicKey)
	require.NoError(t, err)

	old, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: oldPEM, JWTKeyID: "old"})
	require.NoError(t, err)
	token, err := old.Sign("at+jwt", accessClaims())
	require.NoError(t, err)

	rotated, err := NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: ecPEM(t), JWTKeyID: "new", RetainedJWTKeys: []types.JWTVerificationKey{{
		ID: "old", Algorithm: types.JWTAlgorithmES256, PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: oldPub}), NotAfter: time.Now().Add(time.Hour),
	}}})
	require.NoError(t, err)
	_, err = rotated.Verify("at+jwt", token)
	require.NoError(t, err)
	require.Len(t, rotated.JWKS().Keys, 2)

	_, err = NewTokenSigner(types.SecurityConfig{JWTPrivateKeyPEM: ecPEM(t), RetainedJWTKeys: []types.JWTVerificationKey{{
		ID: "hmac", Algorithm: types.JWTAlgorithmHS256, Secret: "01234567890123456789012345678901", NotAfter: time.Now().Add(time.Hour),
	}}})
	require.ErrorContains(t, err, "RS256 or ES256")
}
