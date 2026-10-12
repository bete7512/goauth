package security

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestJWTKeyRotationWindow(t *testing.T) {
	oldConfig := types.SecurityConfig{JWTKeyID: "old", JwtSecretKey: strings.Repeat("a", 32), Session: types.SessionConfig{AccessTokenTTL: time.Hour}}
	old := NewSecurityManager(oldConfig)
	token, err := old.GenerateAccessToken(*testUser(), nil)
	require.NoError(t, err)
	nextConfig := oldConfig
	nextConfig.JWTKeyID, nextConfig.JwtSecretKey = "next", strings.Repeat("b", 32)
	nextConfig.RetainedJWTKeys = []types.JWTVerificationKey{{ID: "old", Algorithm: types.JWTAlgorithmHS256, Secret: oldConfig.JwtSecretKey, NotAfter: time.Now().Add(time.Hour)}}
	next := NewSecurityManager(nextConfig)
	require.NoError(t, next.JWTKeyringError())
	_, err = next.ValidateJWTToken(token)
	require.NoError(t, err, "an overlapping replica must verify the previous signer")
	newToken, err := next.GenerateAccessToken(*testUser(), nil)
	require.NoError(t, err)
	_, err = old.ValidateJWTToken(newToken)
	require.Error(t, err, "an unknown kid must not fall back to the active key")
	nextConfig.RetainedJWTKeys[0].NotAfter = time.Now().Add(-time.Second)
	retired := NewSecurityManager(nextConfig)
	_, err = retired.ValidateJWTToken(token)
	require.Error(t, err)
	_, err = retired.ValidateJWTToken(newToken)
	require.NoError(t, err)
}

func TestEncryptionRotationAndAuthenticatedKeyID(t *testing.T) {
	old := NewSecurityManager(types.SecurityConfig{EncryptionKeyID: "old", EncryptionKey: strings.Repeat("a", 32)})
	ciphertext, err := old.Encrypt("stored MFA secret")
	require.NoError(t, err)
	next := NewSecurityManager(types.SecurityConfig{EncryptionKeyID: "next", EncryptionKey: strings.Repeat("b", 32), DecryptionKeys: map[string]string{"old": strings.Repeat("a", 32)}})
	plaintext, err := next.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, "stored MFA secret", plaintext)
	reencrypted, err := next.Encrypt(plaintext)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(reencrypted, "v1."+base64.RawURLEncoding.EncodeToString([]byte("next"))+"."))
	delete(next.Config.DecryptionKeys, "old")
	_, err = next.Decrypt(ciphertext)
	require.Error(t, err)
	plaintext, err = next.Decrypt(reencrypted)
	require.NoError(t, err)
	require.Equal(t, "stored MFA secret", plaintext)
	// Even a second ID configured with the same secret cannot substitute headers.
	next.Config.DecryptionKeys["alias"] = next.Config.EncryptionKey
	parts := strings.SplitN(reencrypted, ".", 3)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte("alias"))
	_, err = next.Decrypt(strings.Join(parts, "."))
	require.Error(t, err)
}
