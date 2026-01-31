package services_test

import (
	"strings"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/modules/csrf/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/stretchr/testify/suite"
)

type CSRFServiceSuite struct {
	suite.Suite
}

func TestCSRFServiceSuite(t *testing.T) {
	suite.Run(t, new(CSRFServiceSuite))
}

func (s *CSRFServiceSuite) newService(cfg *config.CSRFModuleConfig) *services.CSRFService {
	return services.NewCSRFService("test-jwt-secret-key", cfg)
}

func (s *CSRFServiceSuite) TestGenerateToken() {
	tests := []struct {
		name string
	}{
		{name: "generates valid token format"},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc := s.newService(nil)
			token, err := svc.GenerateToken()

			s.NoError(err)
			s.NotEmpty(token)

			// Token should have 3 parts: nonce:timestamp:signature
			parts := strings.SplitN(token, ":", 3)
			s.Len(parts, 3)
			s.NotEmpty(parts[0], "nonce should not be empty")
			s.NotEmpty(parts[1], "timestamp should not be empty")
			s.NotEmpty(parts[2], "signature should not be empty")
		})
	}
}

func (s *CSRFServiceSuite) TestGenerateTokenUniqueness() {
	svc := s.newService(nil)

	token1, err1 := svc.GenerateToken()
	token2, err2 := svc.GenerateToken()

	s.NoError(err1)
	s.NoError(err2)
	s.NotEqual(token1, token2, "each token should have a unique nonce")
}

func (s *CSRFServiceSuite) TestValidateToken() {
	tests := []struct {
		name    string
		token   func(*services.CSRFService) string
		want    bool
	}{
		{
			name: "valid token",
			token: func(svc *services.CSRFService) string {
				t, _ := svc.GenerateToken()
				return t
			},
			want: true,
		},
		{
			name:  "empty token",
			token: func(_ *services.CSRFService) string { return "" },
			want:  false,
		},
		{
			name:  "garbage token",
			token: func(_ *services.CSRFService) string { return "not-a-valid-token" },
			want:  false,
		},
		{
			name:  "wrong number of parts",
			token: func(_ *services.CSRFService) string { return "part1:part2" },
			want:  false,
		},
		{
			name: "tampered signature",
			token: func(svc *services.CSRFService) string {
				t, _ := svc.GenerateToken()
				parts := strings.SplitN(t, ":", 3)
				return parts[0] + ":" + parts[1] + ":tampered"
			},
			want: false,
		},
		{
			name: "tampered nonce",
			token: func(svc *services.CSRFService) string {
				t, _ := svc.GenerateToken()
				parts := strings.SplitN(t, ":", 3)
				return "tampered:" + parts[1] + ":" + parts[2]
			},
			want: false,
		},
		{
			name: "tampered timestamp",
			token: func(svc *services.CSRFService) string {
				t, _ := svc.GenerateToken()
				parts := strings.SplitN(t, ":", 3)
				return parts[0] + ":9999999999:" + parts[2]
			},
			want: false,
		},
		{
			name:  "non-numeric timestamp",
			token: func(_ *services.CSRFService) string { return "nonce:notanumber:sig" },
			want:  false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc := s.newService(nil)
			token := tt.token(svc)
			s.Equal(tt.want, svc.ValidateToken(token))
		})
	}
}

func (s *CSRFServiceSuite) TestTokenExpiry() {
	cfg := &config.CSRFModuleConfig{
		TokenExpiry: 1 * time.Second,
	}
	svc := s.newService(cfg)

	token, err := svc.GenerateToken()
	s.NoError(err)
	s.True(svc.ValidateToken(token), "should be valid immediately")

	time.Sleep(1100 * time.Millisecond)
	s.False(svc.ValidateToken(token), "should be expired after TTL")
}

func (s *CSRFServiceSuite) TestDifferentKeysDifferentTokens() {
	svc1 := services.NewCSRFService("secret-key-1", nil)
	svc2 := services.NewCSRFService("secret-key-2", nil)

	token, _ := svc1.GenerateToken()

	s.True(svc1.ValidateToken(token), "should validate with same key")
	s.False(svc2.ValidateToken(token), "should reject with different key")
}

func (s *CSRFServiceSuite) TestTokensMatch() {
	svc := s.newService(nil)

	token, _ := svc.GenerateToken()

	s.True(svc.TokensMatch(token, token), "identical tokens should match")
	s.False(svc.TokensMatch(token, "different"), "different tokens should not match")
	s.False(svc.TokensMatch("", ""), "empty tokens should not match")
}

func (s *CSRFServiceSuite) TestConfigDefaults() {
	svc := s.newService(nil)

	s.Equal("__goauth_csrf", svc.CookieName())
	s.Equal("X-CSRF-Token", svc.HeaderName())
	s.Equal("csrf_token", svc.FormFieldName())
	s.Equal("/", svc.CookiePath())
	s.Equal("", svc.CookieDomain())
	s.Equal(1*time.Hour, svc.TokenExpiry())
}

func (s *CSRFServiceSuite) TestConfigOverrides() {
	cfg := &config.CSRFModuleConfig{
		TokenExpiry:   30 * time.Minute,
		CookieName:    "my_csrf",
		HeaderName:    "X-My-CSRF",
		FormFieldName: "my_token",
		CookiePath:    "/api",
		CookieDomain:  "example.com",
	}
	svc := s.newService(cfg)

	s.Equal("my_csrf", svc.CookieName())
	s.Equal("X-My-CSRF", svc.HeaderName())
	s.Equal("my_token", svc.FormFieldName())
	s.Equal("/api", svc.CookiePath())
	s.Equal("example.com", svc.CookieDomain())
	s.Equal(30*time.Minute, svc.TokenExpiry())
}

func (s *CSRFServiceSuite) TestDeriveKey() {
	key1 := services.DeriveKey("secret-a")
	key2 := services.DeriveKey("secret-b")
	key1Again := services.DeriveKey("secret-a")

	s.Len(key1, 32, "derived key should be 32 bytes (SHA-256)")
	s.NotEqual(key1, key2, "different secrets should produce different keys")
	s.Equal(key1, key1Again, "same secret should produce same key")
}
