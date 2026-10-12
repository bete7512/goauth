package security

import (
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCredentialProfiles(t *testing.T) {
	sm := NewSecurityManager(types.SecurityConfig{JwtSecretKey: "01234567890123456789012345678901", Session: types.SessionConfig{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour}})
	user := &models.User{ID: "alice"}
	access, err := sm.GenerateAccessToken(*user, nil)
	require.NoError(t, err)
	_, err = ValidateCredential(sm, access, "access")
	require.NoError(t, err)
	refresh, _, err := sm.GenerateStatelessRefreshToken(user)
	require.NoError(t, err)
	_, err = ValidateCredential(sm, refresh, "access")
	require.Error(t, err)
	_, err = ValidateCredential(sm, access, "refresh")
	require.Error(t, err)
	for _, name := range []string{"type", "user_id", "sub", "exp", "iss", "aud", "token_version"} {
		_, err := sm.GenerateAccessToken(*user, map[string]interface{}{name: "override"})
		require.Error(t, err, name)
	}
	for _, name := range []string{"exp", "iss", "aud", "sub"} {
		claims := jwt.MapClaims{"user_id": "alice", "sub": "alice", "type": "access", "iss": "goauth", "aud": "goauth", "exp": time.Now().Add(time.Hour).Unix()}
		delete(claims, name)
		token, err := sm.signJWT(claims)
		require.NoError(t, err)
		_, err = ValidateCredential(sm, token, "access")
		require.Error(t, err, name)
	}
}

func TestInvalidKeyNeverFallsBack(t *testing.T) {
	sm := NewSecurityManager(types.SecurityConfig{JWTAlgorithm: types.JWTAlgorithmRS256, JWTPrivateKeyPEM: []byte("invalid"), JwtSecretKey: "01234567890123456789012345678901"})
	require.Error(t, sm.JWTKeyringError())
	_, err := sm.GenerateAccessToken(models.User{ID: "alice"}, nil)
	require.Error(t, err)
}
