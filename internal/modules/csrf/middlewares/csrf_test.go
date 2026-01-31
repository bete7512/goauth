package middlewares_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/modules/csrf/middlewares"
	"github.com/bete7512/goauth/internal/modules/csrf/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/stretchr/testify/suite"
)

type CSRFMiddlewareSuite struct {
	suite.Suite
}

func TestCSRFMiddlewareSuite(t *testing.T) {
	suite.Run(t, new(CSRFMiddlewareSuite))
}

func (s *CSRFMiddlewareSuite) newService(cfg *config.CSRFModuleConfig) *services.CSRFService {
	return services.NewCSRFService("test-jwt-secret-key", cfg)
}

func (s *CSRFMiddlewareSuite) setup(cfg *config.CSRFModuleConfig) (*services.CSRFService, func(http.Handler) http.Handler) {
	if cfg == nil {
		cfg = &config.CSRFModuleConfig{}
	}
	svc := s.newService(cfg)
	mw := middlewares.NewCSRFMiddleware(svc, cfg)
	return svc, mw
}

func (s *CSRFMiddlewareSuite) okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func (s *CSRFMiddlewareSuite) TestDoubleSubmit() {
	tests := []struct {
		name           string
		method         string
		cookieToken    string
		headerToken    string
		formToken      string
		wantStatus     int
	}{
		{
			name:        "valid double-submit via header",
			method:      http.MethodPost,
			cookieToken: "VALID",
			headerToken: "VALID",
			wantStatus:  http.StatusOK,
		},
		{
			name:       "valid double-submit via form field",
			method:     http.MethodPost,
			cookieToken: "VALID",
			formToken:  "VALID",
			wantStatus: http.StatusOK,
		},
		{
			name:        "missing cookie",
			method:      http.MethodPost,
			headerToken: "VALID",
			wantStatus:  http.StatusForbidden,
		},
		{
			name:        "missing header and form",
			method:      http.MethodPost,
			cookieToken: "VALID",
			wantStatus:  http.StatusForbidden,
		},
		{
			name:        "cookie and header mismatch",
			method:      http.MethodPost,
			cookieToken: "VALID",
			headerToken: "DIFFERENT",
			wantStatus:  http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mw := s.setup(nil)

			// Generate a real token for "VALID" placeholders
			realToken, err := svc.GenerateToken()
			s.NoError(err)

			resolve := func(val string) string {
				if val == "VALID" {
					return realToken
				}
				return val
			}

			req := httptest.NewRequest(tt.method, "/api/v1/something", nil)
			if tt.cookieToken != "" {
				req.AddCookie(&http.Cookie{
					Name:  svc.CookieName(),
					Value: resolve(tt.cookieToken),
				})
			}
			if tt.headerToken != "" {
				req.Header.Set(svc.HeaderName(), resolve(tt.headerToken))
			}
			if tt.formToken != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Form = map[string][]string{
					svc.FormFieldName(): {resolve(tt.formToken)},
				}
			}

			rr := httptest.NewRecorder()
			mw(s.okHandler()).ServeHTTP(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

func (s *CSRFMiddlewareSuite) TestSafeMethodsSkipped() {
	tests := []struct {
		name   string
		method string
	}{
		{name: "GET", method: http.MethodGet},
		{name: "HEAD", method: http.MethodHead},
		{name: "OPTIONS", method: http.MethodOptions},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			_, mw := s.setup(nil)

			req := httptest.NewRequest(tt.method, "/api/v1/something", nil)
			// No CSRF tokens at all — safe methods should pass
			rr := httptest.NewRecorder()
			mw(s.okHandler()).ServeHTTP(rr, req)

			s.Equal(http.StatusOK, rr.Code)
		})
	}
}

func (s *CSRFMiddlewareSuite) TestProtectedMethods() {
	tests := []struct {
		name   string
		method string
	}{
		{name: "POST", method: http.MethodPost},
		{name: "PUT", method: http.MethodPut},
		{name: "DELETE", method: http.MethodDelete},
		{name: "PATCH", method: http.MethodPatch},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			_, mw := s.setup(nil)

			req := httptest.NewRequest(tt.method, "/api/v1/something", nil)
			// No tokens — should be rejected
			rr := httptest.NewRecorder()
			mw(s.okHandler()).ServeHTTP(rr, req)

			s.Equal(http.StatusForbidden, rr.Code)
		})
	}
}

func (s *CSRFMiddlewareSuite) TestExcludePaths() {
	cfg := &config.CSRFModuleConfig{
		ExcludePaths: []string{"/api/v1/webhooks", "/api/v1/health"},
	}
	_, mw := s.setup(cfg)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{
			name:       "excluded path passes without token",
			path:       "/api/v1/webhooks/stripe",
			wantStatus: http.StatusOK,
		},
		{
			name:       "another excluded path",
			path:       "/api/v1/health",
			wantStatus: http.StatusOK,
		},
		{
			name:       "non-excluded path is protected",
			path:       "/api/v1/users",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			rr := httptest.NewRecorder()
			mw(s.okHandler()).ServeHTTP(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

func (s *CSRFMiddlewareSuite) TestCustomProtectedMethods() {
	cfg := &config.CSRFModuleConfig{
		ProtectedMethods: []string{"POST"}, // Only POST, not PUT/DELETE/PATCH
	}
	_, mw := s.setup(cfg)

	tests := []struct {
		name       string
		method     string
		wantStatus int
	}{
		{
			name:       "POST is protected",
			method:     http.MethodPost,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "PUT is not protected with custom config",
			method:     http.MethodPut,
			wantStatus: http.StatusOK,
		},
		{
			name:       "DELETE is not protected with custom config",
			method:     http.MethodDelete,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			req := httptest.NewRequest(tt.method, "/api/v1/something", nil)
			rr := httptest.NewRecorder()
			mw(s.okHandler()).ServeHTTP(rr, req)

			s.Equal(tt.wantStatus, rr.Code)
		})
	}
}

func (s *CSRFMiddlewareSuite) TestExpiredTokenRejected() {
	// Use a service with very short TTL for both middleware and token generation
	cfg := &config.CSRFModuleConfig{
		TokenExpiry: 1 * time.Millisecond,
	}
	svc, mw := s.setup(cfg)

	token, _ := svc.GenerateToken()
	time.Sleep(10 * time.Millisecond) // ensure expired

	req := httptest.NewRequest(http.MethodPost, "/api/v1/something", nil)
	req.AddCookie(&http.Cookie{Name: svc.CookieName(), Value: token})
	req.Header.Set(svc.HeaderName(), token)

	rr := httptest.NewRecorder()
	mw(s.okHandler()).ServeHTTP(rr, req)

	s.Equal(http.StatusForbidden, rr.Code)
}

func (s *CSRFMiddlewareSuite) TestCookieOnlyDoesNotPass() {
	svc, mw := s.setup(nil)

	token, _ := svc.GenerateToken()

	// Only set cookie, no header or form — should fail
	req := httptest.NewRequest(http.MethodPost, "/api/v1/something", nil)
	req.AddCookie(&http.Cookie{Name: svc.CookieName(), Value: token})

	rr := httptest.NewRecorder()
	mw(s.okHandler()).ServeHTTP(rr, req)

	s.Equal(http.StatusForbidden, rr.Code, "cookie-only should NOT pass — this is the core CSRF defense")
}
