package csrf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/caches"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type csrfTokenData struct {
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CSRFManager struct {
	Auth config.Auth
}

func New(auth config.Auth) (interfaces.CSRFManager, error) {
	// Create cache factory
	cacheFactory, err := caches.NewCacheFactory(*auth.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache factory: %v", err)
	}

	cache := cacheFactory.GetCache()
	if cache == nil {
		return nil, fmt.Errorf("failed to create cache instance")
	}

	return &CSRFManager{
		Auth: auth,
	}, nil
}

func (m *CSRFManager) GenerateToken(ctx context.Context, userID string) (string, error) {
	// Generate random token
	tokenBytes := make([]byte, m.Auth.Config.Security.CSRF.TokenLength/2)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	// Create token data
	tokenData := csrfTokenData{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(m.Auth.Config.Security.CSRF.TokenTTL),
	}

	// Serialize token data
	data, err := json.Marshal(tokenData)
	if err != nil {
		return "", err
	}

	// Store in cache with TTL
	key := fmt.Sprintf("csrf:%s", token)
	err = m.Auth.Cache.Set(ctx, key, string(data), m.Auth.Config.Security.CSRF.TokenTTL)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (m *CSRFManager) ValidateToken(ctx context.Context, token string, userID string) (bool, error) {
	key := fmt.Sprintf("csrf:%s", token)

	// Get token from cache
	data, err := m.Auth.Cache.Get(ctx, key)
	if err != nil {
		return false, nil // Token not found
	}

	// Deserialize token data
	var tokenData csrfTokenData
	if err := json.Unmarshal([]byte(data.(string)), &tokenData); err != nil {
		return false, err
	}

	// Check if token is expired
	if time.Now().After(tokenData.ExpiresAt) {
		// Remove expired token
		m.Auth.Cache.Delete(ctx, key)
		return false, nil
	}

	// Check if token belongs to the user
	return tokenData.UserID == userID, nil
}

func (m *CSRFManager) RevokeToken(ctx context.Context, token string) error {
	key := fmt.Sprintf("csrf:%s", token)
	return m.Auth.Cache.Delete(ctx, key)
}

func (m *CSRFManager) Close() error {
	return m.Auth.Cache.Close()
}
