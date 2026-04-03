package services_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/modules/captcha/services"
	"github.com/stretchr/testify/suite"
)

type CaptchaServiceSuite struct {
	suite.Suite
}

func TestCaptchaServiceSuite(t *testing.T) {
	suite.Run(t, new(CaptchaServiceSuite))
}

func (s *CaptchaServiceSuite) TestNilProviderReturnsError() {
	svc := services.NewCaptchaService(nil)
	ok, err := svc.Verify(context.Background(), "token", "1.2.3.4")
	s.False(ok)
	s.Error(err)
	s.Contains(err.Error(), "no provider configured")
}

func (s *CaptchaServiceSuite) TestProviderAccessor() {
	svc := services.NewCaptchaService(nil)
	s.Nil(svc.Provider())

	provider := services.NewGoogleProvider("secret", 0.5, 0)
	svc2 := services.NewCaptchaService(provider)
	s.NotNil(svc2.Provider())
}

// --- Google reCAPTCHA v3 tests ---

func (s *CaptchaServiceSuite) googleServer(handler http.HandlerFunc) (*httptest.Server, *services.GoogleProvider) {
	srv := httptest.NewServer(handler)
	p := services.NewGoogleProvider("test-secret", 0.5, 5*time.Second)
	// Override the verify URL to point at our test server
	p.SetVerifyURL(srv.URL)
	return srv, p
}

func (s *CaptchaServiceSuite) TestGoogleProvider() {
	tests := []struct {
		name      string
		response  map[string]interface{}
		wantValid bool
		wantErr   bool
	}{
		{
			name: "valid token with high score",
			response: map[string]interface{}{
				"success": true,
				"score":   0.9,
			},
			wantValid: true,
			wantErr:   false,
		},
		{
			name: "valid token at threshold",
			response: map[string]interface{}{
				"success": true,
				"score":   0.5,
			},
			wantValid: true,
			wantErr:   false,
		},
		{
			name: "score below threshold",
			response: map[string]interface{}{
				"success": true,
				"score":   0.3,
			},
			wantValid: false,
			wantErr:   false,
		},
		{
			name: "verification failed",
			response: map[string]interface{}{
				"success":     false,
				"error-codes": []string{"invalid-input-secret"},
			},
			wantValid: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			srv, provider := s.googleServer(func(w http.ResponseWriter, r *http.Request) {
				s.Equal(http.MethodPost, r.Method)
				s.Equal("application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				s.NoError(r.ParseForm())
				s.Equal("test-secret", r.PostFormValue("secret"))
				s.Equal("test-token", r.PostFormValue("response"))
				s.Equal("1.2.3.4", r.PostFormValue("remoteip"))

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.response)
			})
			defer srv.Close()

			valid, err := provider.Verify(context.Background(), "test-token", "1.2.3.4")
			s.Equal(tt.wantValid, valid)
			if tt.wantErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *CaptchaServiceSuite) TestGoogleProviderDefaultThreshold() {
	// Threshold <= 0 defaults to 0.5
	p := services.NewGoogleProvider("secret", 0, 0)
	s.NotNil(p)
}

func (s *CaptchaServiceSuite) TestGoogleProviderAPIError() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p := services.NewGoogleProvider("secret", 0.5, 5*time.Second)
	p.SetVerifyURL(srv.URL)

	valid, err := p.Verify(context.Background(), "token", "1.2.3.4")
	s.False(valid)
	s.Error(err)
}

// --- Cloudflare Turnstile tests ---

func (s *CaptchaServiceSuite) cloudflareServer(handler http.HandlerFunc) (*httptest.Server, *services.CloudflareProvider) {
	srv := httptest.NewServer(handler)
	p := services.NewCloudflareProvider("test-secret", 5*time.Second)
	p.SetVerifyURL(srv.URL)
	return srv, p
}

func (s *CaptchaServiceSuite) TestCloudflareProvider() {
	tests := []struct {
		name      string
		response  map[string]interface{}
		wantValid bool
		wantErr   bool
	}{
		{
			name: "valid token",
			response: map[string]interface{}{
				"success": true,
			},
			wantValid: true,
			wantErr:   false,
		},
		{
			name: "verification failed",
			response: map[string]interface{}{
				"success":     false,
				"error-codes": []string{"invalid-input-response"},
			},
			wantValid: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			srv, provider := s.cloudflareServer(func(w http.ResponseWriter, r *http.Request) {
				s.Equal(http.MethodPost, r.Method)
				s.Equal("application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				s.NoError(r.ParseForm())
				s.Equal("test-secret", r.PostFormValue("secret"))
				s.Equal("test-token", r.PostFormValue("response"))

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(tt.response)
			})
			defer srv.Close()

			valid, err := provider.Verify(context.Background(), "test-token", "1.2.3.4")
			s.Equal(tt.wantValid, valid)
			if tt.wantErr {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *CaptchaServiceSuite) TestCloudflareProviderAPIError() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("bad response"))
	}))
	defer srv.Close()

	p := services.NewCloudflareProvider("secret", 5*time.Second)
	p.SetVerifyURL(srv.URL)

	valid, err := p.Verify(context.Background(), "token", "1.2.3.4")
	s.False(valid)
	s.Error(err)
}
