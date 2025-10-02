package services

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type CSRFService struct {
	tokenLength   int
	tokenExpiry   int
	cookieName    string
	headerName    string
	formFieldName string
	tokens        map[string]time.Time
	mu            sync.RWMutex
}

func NewCSRFService(tokenLength, tokenExpiry int, cookieName, headerName, formFieldName string) *CSRFService {
	service := &CSRFService{
		tokenLength:   tokenLength,
		tokenExpiry:   tokenExpiry,
		cookieName:    cookieName,
		headerName:    headerName,
		formFieldName: formFieldName,
		tokens:        make(map[string]time.Time),
	}

	// Start cleanup goroutine
	go service.cleanup()

	return service
}

// GenerateToken generates a new CSRF token
func (s *CSRFService) GenerateToken() (string, error) {
	b := make([]byte, s.tokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	token := base64.URLEncoding.EncodeToString(b)

	// Store token with expiry
	s.mu.Lock()
	s.tokens[token] = time.Now().Add(time.Duration(s.tokenExpiry) * time.Second)
	s.mu.Unlock()

	return token, nil
}

// ValidateToken validates a CSRF token
func (s *CSRFService) ValidateToken(token string) bool {
	if token == "" {
		return false
	}

	s.mu.RLock()
	expiry, exists := s.tokens[token]
	s.mu.RUnlock()

	if !exists {
		return false
	}

	// Check if token has expired
	if time.Now().After(expiry) {
		// Remove expired token
		s.mu.Lock()
		delete(s.tokens, token)
		s.mu.Unlock()
		return false
	}

	return true
}

// InvalidateToken removes a token (after use)
func (s *CSRFService) InvalidateToken(token string) {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
}

// cleanup removes expired tokens
func (s *CSRFService) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, expiry := range s.tokens {
			if now.After(expiry) {
				delete(s.tokens, token)
			}
		}
		s.mu.Unlock()
	}
}

// GetCookieName returns the CSRF cookie name
func (s *CSRFService) GetCookieName() string {
	return s.cookieName
}

// GetHeaderName returns the CSRF header name
func (s *CSRFService) GetHeaderName() string {
	return s.headerName
}

// GetFormFieldName returns the CSRF form field name
func (s *CSRFService) GetFormFieldName() string {
	return s.formFieldName
}
