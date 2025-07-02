package csrf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type memoryCSRFManager struct {
	conf     config.Config
	tokens   map[string]csrfToken
	mutex    sync.RWMutex
	stopChan chan struct{}
}

type csrfToken struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
}

func NewMemoryCSRFManager(conf config.Config) (interfaces.CSRFManager, error) {
	manager := &memoryCSRFManager{
		conf:     conf,
		tokens:   make(map[string]csrfToken),
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	go manager.cleanupExpiredTokens()

	return manager, nil
}

func (m *memoryCSRFManager) GenerateToken(ctx context.Context, userID string) (string, error) {
	// Generate random token
	tokenBytes := make([]byte, m.conf.Security.CSRF.TokenLength/2)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	// Store token
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.tokens[token] = csrfToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(m.conf.Security.CSRF.TokenTTL),
	}

	return token, nil
}

func (m *memoryCSRFManager) ValidateToken(ctx context.Context, token string, userID string) (bool, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	storedToken, exists := m.tokens[token]
	if !exists {
		return false, nil
	}

	// Check if token is expired
	if time.Now().After(storedToken.ExpiresAt) {
		// Remove expired token
		m.mutex.RUnlock()
		m.mutex.Lock()
		delete(m.tokens, token)
		m.mutex.Unlock()
		m.mutex.RLock()
		return false, nil
	}

	// Check if token belongs to the user
	return storedToken.UserID == userID, nil
}

func (m *memoryCSRFManager) RevokeToken(ctx context.Context, token string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.tokens, token)
	return nil
}

func (m *memoryCSRFManager) Close() error {
	close(m.stopChan)
	return nil
}

func (m *memoryCSRFManager) cleanupExpiredTokens() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mutex.Lock()
			now := time.Now()
			for token, tokenData := range m.tokens {
				if now.After(tokenData.ExpiresAt) {
					delete(m.tokens, token)
				}
			}
			m.mutex.Unlock()
		case <-m.stopChan:
			return
		}
	}
}
