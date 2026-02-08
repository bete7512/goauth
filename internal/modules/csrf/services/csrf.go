package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/config"
)

const (
	defaultTokenExpiry   = 1 * time.Hour
	defaultCookieName    = "__goauth_csrf"
	defaultHeaderName    = "X-CSRF-Token"
	defaultFormFieldName = "csrf_token"
	defaultCookiePath    = "/"
	nonceLength          = 32
	tokenParts           = 3 // nonce:timestamp:signature
)

//go:generate mockgen -destination=../../../mocks/mock_csrf_service.go -package=mocks github.com/bete7512/goauth/internal/modules/csrf/services CSRFService

// CSRFService defines the CSRF token operations.
type CSRFService interface {
	GenerateToken() (string, error)
	ValidateToken(token string) bool
	TokensMatch(a, b string) bool
	CookieName() string
	HeaderName() string
	FormFieldName() string
	TokenExpiry() time.Duration
	CookiePath() string
	CookieDomain() string
}

// csrfService provides stateless HMAC-based CSRF token generation and validation.
// Tokens are self-contained — no server-side storage is needed.
type csrfService struct {
	secretKey     []byte
	tokenExpiry   time.Duration
	cookieName    string
	headerName    string
	formFieldName string
	cookiePath    string
	cookieDomain  string
}

// DeriveKey derives a CSRF-specific key from the JWT secret key using HMAC-SHA256.
// This avoids using the raw JWT key directly for CSRF operations.
func DeriveKey(jwtSecretKey string) []byte {
	mac := hmac.New(sha256.New, []byte(jwtSecretKey))
	mac.Write([]byte("goauth-csrf-key"))
	return mac.Sum(nil)
}

// NewCSRFService creates a new CSRF service with HMAC-based token generation.
func NewCSRFService(jwtSecretKey string, cfg *config.CSRFModuleConfig) *csrfService {
	s := &csrfService{
		secretKey:     DeriveKey(jwtSecretKey),
		tokenExpiry:   defaultTokenExpiry,
		cookieName:    defaultCookieName,
		headerName:    defaultHeaderName,
		formFieldName: defaultFormFieldName,
		cookiePath:    defaultCookiePath,
	}

	if cfg == nil {
		return s
	}

	if cfg.TokenExpiry > 0 {
		s.tokenExpiry = cfg.TokenExpiry
	}
	if cfg.CookieName != "" {
		s.cookieName = cfg.CookieName
	}
	if cfg.HeaderName != "" {
		s.headerName = cfg.HeaderName
	}
	if cfg.FormFieldName != "" {
		s.formFieldName = cfg.FormFieldName
	}
	if cfg.CookiePath != "" {
		s.cookiePath = cfg.CookiePath
	}
	if cfg.CookieDomain != "" {
		s.cookieDomain = cfg.CookieDomain
	}

	return s
}

// GenerateToken creates a new HMAC-signed CSRF token.
// Format: base64(nonce):unix_timestamp:base64(hmac_signature)
func (s *csrfService) GenerateToken() (string, error) {
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("csrf: failed to generate nonce: %w", err)
	}

	nonceB64 := base64.RawURLEncoding.EncodeToString(nonce)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	payload := nonceB64 + ":" + timestamp

	sig := s.sign(payload)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return payload + ":" + sigB64, nil
}

// ValidateToken checks that a token has a valid HMAC signature and hasn't expired.
func (s *csrfService) ValidateToken(token string) bool {
	if token == "" {
		return false
	}

	parts := strings.SplitN(token, ":", tokenParts)
	if len(parts) != tokenParts {
		return false
	}

	nonceB64, timestampStr, sigB64 := parts[0], parts[1], parts[2]

	// Check expiry
	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(ts, 0)) > s.tokenExpiry {
		return false
	}

	// Recompute HMAC and compare
	payload := nonceB64 + ":" + timestampStr
	expectedSig := s.sign(payload)

	actualSig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(expectedSig, actualSig) == 1
}

// TokensMatch compares two tokens using constant-time comparison.
// Returns false if either token is empty.
func (s *csrfService) TokensMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *csrfService) sign(payload string) []byte {
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// CookieName returns the configured CSRF cookie name.
func (s *csrfService) CookieName() string { return s.cookieName }

// HeaderName returns the configured CSRF header name.
func (s *csrfService) HeaderName() string { return s.headerName }

// FormFieldName returns the configured CSRF form field name.
func (s *csrfService) FormFieldName() string { return s.formFieldName }

// TokenExpiry returns the configured token expiry duration.
func (s *csrfService) TokenExpiry() time.Duration { return s.tokenExpiry }

// CookiePath returns the configured cookie path.
func (s *csrfService) CookiePath() string { return s.cookiePath }

// CookieDomain returns the configured cookie domain.
func (s *csrfService) CookieDomain() string { return s.cookieDomain }
