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

type redisCSRFManager struct {
	conf   config.Config
	client *caches.RedisClient
}

type csrfTokenData struct {
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewRedisCSRFManager(conf config.Config) (interfaces.CSRFManager, error) {
	client := caches.NewRedisClient(conf.Redis)
	if client == nil {
		return nil, fmt.Errorf("failed to create redis client")
	}

	return &redisCSRFManager{
		conf:   conf,
		client: client,
	}, nil
}

func (m *redisCSRFManager) GenerateToken(ctx context.Context, userID string) (string, error) {
	// Generate random token
	tokenBytes := make([]byte, m.conf.Security.CSRF.TokenLength/2)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	// Create token data
	tokenData := csrfTokenData{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(m.conf.Security.CSRF.TokenTTL),
	}

	// Serialize token data
	data, err := json.Marshal(tokenData)
	if err != nil {
		return "", err
	}

	// Store in Redis with TTL
	key := fmt.Sprintf("csrf:%s", token)
	err = m.client.Set(key, string(data), m.conf.Security.CSRF.TokenTTL)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (m *redisCSRFManager) ValidateToken(ctx context.Context, token string, userID string) (bool, error) {
	key := fmt.Sprintf("csrf:%s", token)

	// Get token from Redis
	data, err := m.client.Get(key)
	if err != nil {
		return false, nil // Token not found
	}

	// Deserialize token data
	var tokenData csrfTokenData
	if err := json.Unmarshal([]byte(data), &tokenData); err != nil {
		return false, err
	}

	// Check if token is expired
	if time.Now().After(tokenData.ExpiresAt) {
		// Remove expired token
		m.client.Del(key)
		return false, nil
	}

	// Check if token belongs to the user
	return tokenData.UserID == userID, nil
}

func (m *redisCSRFManager) RevokeToken(ctx context.Context, token string) error {
	key := fmt.Sprintf("csrf:%s", token)
	return m.client.Del(key)
}

func (m *redisCSRFManager) Close() error {
	return m.client.Close()
}
