package handlers_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/csrf/handlers"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type CSRFHandlerSuite struct {
	suite.Suite
}

func TestCSRFHandlerSuite(t *testing.T) {
	suite.Run(t, new(CSRFHandlerSuite))
}

func (s *CSRFHandlerSuite) setupHandler(cfg *config.CSRFModuleConfig) (*handlers.CSRFHandler, *mocks.MockCSRFService) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockService := mocks.NewMockCSRFService(ctrl)

	if cfg == nil {
		cfg = &config.CSRFModuleConfig{}
	}

	handler := handlers.NewCSRFHandler(mockService, cfg)
	return handler, mockService
}

// ---------------------------------------------------------------------------
// GetToken
// ---------------------------------------------------------------------------

func (s *CSRFHandlerSuite) TestGetToken() {
	tests := []struct {
		name       string
		setup      func(*mocks.MockCSRFService)
		wantStatus int
		wantCookie bool
	}{
		{
			name: "success",
			setup: func(svc *mocks.MockCSRFService) {
				svc.EXPECT().GenerateToken().Return("test-csrf-token", nil)
				svc.EXPECT().CookieName().Return("__goauth_csrf")
				svc.EXPECT().CookiePath().Return("/")
				svc.EXPECT().CookieDomain().Return("")
				svc.EXPECT().TokenExpiry().Return(1 * time.Hour)
			},
			wantStatus: http.StatusOK,
			wantCookie: true,
		},
		{
			name: "token generation fails",
			setup: func(svc *mocks.MockCSRFService) {
				svc.EXPECT().GenerateToken().Return("", errors.New("entropy failure"))
			},
			wantStatus: http.StatusInternalServerError,
			wantCookie: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			handler, mockService := s.setupHandler(nil)
			tt.setup(mockService)

			req := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
			rr := httptest.NewRecorder()

			handler.GetToken(rr, req)

			s.Equal(tt.wantStatus, rr.Code)

			if tt.wantCookie {
				var resp types.APIResponse[map[string]string]
				s.NoError(json.NewDecoder(rr.Body).Decode(&resp))
				s.Equal("test-csrf-token", resp.Data["csrf_token"])

				cookies := rr.Result().Cookies()
				s.NotEmpty(cookies)
				var csrfCookie *http.Cookie
				for _, c := range cookies {
					if c.Name == "__goauth_csrf" {
						csrfCookie = c
						break
					}
				}
				s.NotNil(csrfCookie)
				s.Equal("test-csrf-token", csrfCookie.Value)
				s.Equal("/", csrfCookie.Path)
				s.False(csrfCookie.HttpOnly, "cookie must NOT be HttpOnly for double-submit")
			}
		})
	}
}

func (s *CSRFHandlerSuite) TestGetTokenCookieConfig() {
	cfg := &config.CSRFModuleConfig{
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	handler, mockService := s.setupHandler(cfg)

	mockService.EXPECT().GenerateToken().Return("configured-token", nil)
	mockService.EXPECT().CookieName().Return("my_csrf")
	mockService.EXPECT().CookiePath().Return("/api")
	mockService.EXPECT().CookieDomain().Return("example.com")
	mockService.EXPECT().TokenExpiry().Return(30 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/csrf-token", nil)
	rr := httptest.NewRecorder()

	handler.GetToken(rr, req)

	s.Equal(http.StatusOK, rr.Code)

	cookies := rr.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "my_csrf" {
			csrfCookie = c
			break
		}
	}
	s.NotNil(csrfCookie)
	s.Equal("configured-token", csrfCookie.Value)
	s.Equal("/api", csrfCookie.Path)
	s.Equal("example.com", csrfCookie.Domain)
	s.True(csrfCookie.Secure)
	s.Equal(1800, csrfCookie.MaxAge, "30 minutes in seconds")
}
