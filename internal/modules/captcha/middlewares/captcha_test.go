package middlewares_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bete7512/goauth/internal/modules/captcha/middlewares"
	"github.com/bete7512/goauth/internal/modules/captcha/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/stretchr/testify/suite"
)

// mockProvider implements services.CaptchaProvider for testing.
type mockProvider struct {
	valid bool
	err   error
}

func (m *mockProvider) Verify(_ context.Context, _, _ string) (bool, error) {
	return m.valid, m.err
}

type CaptchaMiddlewareSuite struct {
	suite.Suite
}

func TestCaptchaMiddlewareSuite(t *testing.T) {
	suite.Run(t, new(CaptchaMiddlewareSuite))
}

func (s *CaptchaMiddlewareSuite) okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func (s *CaptchaMiddlewareSuite) setup(provider services.CaptchaProvider, cfg *config.CaptchaModuleConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		cfg = &config.CaptchaModuleConfig{}
	}
	svc := services.NewCaptchaService(provider)
	return middlewares.NewCaptchaMiddleware(svc, cfg)
}

func (s *CaptchaMiddlewareSuite) TestTokenSources() {
	tests := []struct {
		name       string
		setToken   func(r *http.Request)
		wantStatus int
	}{
		{
			name: "token via X-Captcha-Token header",
			setToken: func(r *http.Request) {
				r.Header.Set("X-Captcha-Token", "valid-token")
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "token via captcha_token form field",
			setToken: func(r *http.Request) {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Form = map[string][]string{"captcha_token": {"valid-token"}}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "token via cf-turnstile-response form field",
			setToken: func(r *http.Request) {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Form = map[string][]string{"cf-turnstile-response": {"valid-token"}}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "token via g-recaptcha-response form field",
			setToken: func(r *http.Request) {
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Form = map[string][]string{"g-recaptcha-response": {"valid-token"}}
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing token",
			setToken:   func(r *http.Request) {},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			mw := s.setup(&mockProvider{valid: true}, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", nil)
			tt.setToken(req)

			rr := httptest.NewRecorder()
			mw(s.okHandler()).ServeHTTP(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

func (s *CaptchaMiddlewareSuite) TestMissingTokenErrorFormat() {
	mw := s.setup(&mockProvider{valid: true}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", nil)
	rr := httptest.NewRecorder()
	mw(s.okHandler()).ServeHTTP(rr, req)

	s.Equal(http.StatusForbidden, rr.Code)

	var body map[string]interface{}
	err := json.NewDecoder(rr.Body).Decode(&body)
	s.NoError(err)
	s.Contains(body, "data")

	dataObj, ok := body["data"].(map[string]interface{})
	s.True(ok)
	s.Equal("CAPTCHA_REQUIRED", dataObj["code"])
}

func (s *CaptchaMiddlewareSuite) TestVerificationFailed() {
	mw := s.setup(&mockProvider{valid: false, err: fmt.Errorf("invalid token")}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", nil)
	req.Header.Set("X-Captcha-Token", "bad-token")

	rr := httptest.NewRecorder()
	mw(s.okHandler()).ServeHTTP(rr, req)

	s.Equal(http.StatusForbidden, rr.Code)

	var body map[string]interface{}
	err := json.NewDecoder(rr.Body).Decode(&body)
	s.NoError(err)

	dataObj, ok := body["data"].(map[string]interface{})
	s.True(ok)
	s.Equal("CAPTCHA_FAILED", dataObj["code"])
}

func (s *CaptchaMiddlewareSuite) TestScoreBelowThreshold() {
	// Provider returns valid=false but no error (score too low)
	mw := s.setup(&mockProvider{valid: false, err: nil}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", nil)
	req.Header.Set("X-Captcha-Token", "low-score-token")

	rr := httptest.NewRecorder()
	mw(s.okHandler()).ServeHTTP(rr, req)

	s.Equal(http.StatusForbidden, rr.Code)
}

func (s *CaptchaMiddlewareSuite) TestNilProviderPassesThrough() {
	mw := s.setup(nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", nil)
	// No captcha token — should pass because no provider is configured
	rr := httptest.NewRecorder()
	mw(s.okHandler()).ServeHTTP(rr, req)

	s.Equal(http.StatusOK, rr.Code)
}

func (s *CaptchaMiddlewareSuite) TestCustomHeaderName() {
	cfg := &config.CaptchaModuleConfig{
		HeaderName: "X-My-Captcha",
	}
	mw := s.setup(&mockProvider{valid: true}, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", nil)
	req.Header.Set("X-My-Captcha", "custom-token")

	rr := httptest.NewRecorder()
	mw(s.okHandler()).ServeHTTP(rr, req)

	s.Equal(http.StatusOK, rr.Code)
}

func (s *CaptchaMiddlewareSuite) TestCustomFormFieldName() {
	cfg := &config.CaptchaModuleConfig{
		FormFieldName: "my_captcha",
	}
	mw := s.setup(&mockProvider{valid: true}, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/signup", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Form = map[string][]string{"my_captcha": {"custom-token"}}

	rr := httptest.NewRecorder()
	mw(s.okHandler()).ServeHTTP(rr, req)

	s.Equal(http.StatusOK, rr.Code)
}
