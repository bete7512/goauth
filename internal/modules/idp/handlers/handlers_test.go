package handlers_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/idp/handlers"
	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/idp/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type IDPHandlerSuite struct {
	suite.Suite
}

func TestIDPHandlerSuite(t *testing.T) {
	suite.Run(t, new(IDPHandlerSuite))
}

type noopLogger struct{}

func (noopLogger) Info(string, ...interface{})                      {}
func (noopLogger) Error(string, ...interface{})                     {}
func (noopLogger) Debug(string, ...interface{})                     {}
func (noopLogger) Warn(string, ...interface{})                      {}
func (noopLogger) Trace(string, ...interface{})                     {}
func (noopLogger) Infof(string, ...interface{})                     {}
func (noopLogger) Tracef(string, ...interface{})                    {}
func (noopLogger) Errorf(string, ...interface{})                    {}
func (noopLogger) Debugf(string, ...interface{})                    {}
func (noopLogger) Warnf(string, ...interface{})                     {}
func (noopLogger) Fatalf(string, ...interface{})                    {}
func (l noopLogger) WithFields(map[string]interface{}) types.Logger { return l }

func (s *IDPHandlerSuite) setup(settings *services.Settings) (*handlers.IDPHandler, *mocks.MockIDPService) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)
	service := mocks.NewMockIDPService(ctrl)
	if settings == nil {
		settings = &services.Settings{}
	}
	deps := config.ModuleDependencies{Config: testutil.TestConfig(), Logger: noopLogger{}}
	return handlers.NewIDPHandler(service, deps, settings), service
}

func tokenRequest(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func oauthError(s *IDPHandlerSuite, w *httptest.ResponseRecorder) dto.OAuthError {
	var body dto.OAuthError
	s.Require().NoError(json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func (s *IDPHandlerSuite) TestRoutes() {
	handler, _ := s.setup(nil)
	names := map[string]config.RouteInfo{}
	for _, route := range handler.GetRoutes() {
		_, duplicate := names[route.Name]
		s.False(duplicate, "route name %s is used twice", route.Name)
		names[route.Name] = route
		s.True(strings.HasPrefix(route.Name, "idp."), route.Name)
	}
	s.Len(names, 11, "the admin API is off unless enabled")

	for _, name := range []types.RouteName{types.RouteIDPDiscovery, types.RouteIDPJWKS, types.RouteIDPAuthorize, types.RouteIDPToken, types.RouteIDPUserInfo, types.RouteIDPUserInfoPost} {
		s.Empty(names[string(name)].Middlewares, "%s is a protocol endpoint with its own authentication", name)
	}
	for _, name := range []types.RouteName{types.RouteIDPConsentGet, types.RouteIDPConsentApprove, types.RouteIDPConsentDeny, types.RouteIDPGrantsList, types.RouteIDPGrantsRevoke} {
		s.Equal([]types.MiddlewareName{types.MiddlewareAuth}, names[string(name)].Middlewares, "%s needs a signed-in user", name)
	}

	withAdmin, _ := s.setup(&services.Settings{AdminAPI: true})
	admin := 0
	for _, route := range withAdmin.GetRoutes() {
		if strings.HasPrefix(route.Name, "idp.admin.") {
			admin++
			s.Equal([]types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth}, route.Middlewares, route.Name)
			s.True(strings.HasPrefix(route.Path, "/admin/oidc/"), route.Path)
		}
	}
	s.Equal(6, admin)
}

// An internal failure reaches the client as server_error and nothing more.
func (s *IDPHandlerSuite) TestTokenHidesInternalErrors() {
	handler, service := s.setup(nil)
	service.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil,
		types.NewInternalError("failed to load user").Wrap(errors.New("dial tcp 10.0.0.5:5432: connection refused")))

	w := httptest.NewRecorder()
	handler.Token(w, tokenRequest(url.Values{"grant_type": {"authorization_code"}}))
	s.Equal(http.StatusInternalServerError, w.Code)
	s.Equal("no-store", w.Header().Get("Cache-Control"))
	body := oauthError(s, w)
	s.Equal("server_error", body.Error)
	s.NotContains(w.Body.String(), "10.0.0.5")
	s.NotContains(w.Body.String(), "failed to load user")
}

func (s *IDPHandlerSuite) TestTokenPassesBasicCredentialsDecoded() {
	handler, service := s.setup(nil)
	service.EXPECT().Token(gomock.Any(), gomock.Any()).DoAndReturn(func(_ interface{}, req *services.TokenRequest) (*dto.TokenResponse, *types.GoAuthError) {
		s.True(req.HasBasic)
		s.Equal("my app", req.BasicID)
		s.Equal("p@ss word", req.BasicSecret)
		s.Equal("abc", req.Form.Get("code"))
		s.Empty(req.Form.Get("from_url"), "parameters are read from the body only")
		return &dto.TokenResponse{AccessToken: "token", TokenType: "Bearer", ExpiresIn: 3600}, nil
	})

	req := tokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {"abc"}})
	req.URL.RawQuery = "from_url=1"
	req.SetBasicAuth("my%20app", "p%40ss+word")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	s.Equal(http.StatusOK, w.Code)
	s.Equal("no-store", w.Header().Get("Cache-Control"))
	s.Equal("no-cache", w.Header().Get("Pragma"))
}

func (s *IDPHandlerSuite) TestTokenRequiresAFormBody() {
	handler, _ := s.setup(nil)
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(`{"grant_type":"authorization_code"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Token(w, req)
	s.Equal(http.StatusBadRequest, w.Code)
	s.Equal("invalid_request", oauthError(s, w).Error)
}

func (s *IDPHandlerSuite) TestInvalidClientChallengesWithBasic() {
	handler, service := s.setup(nil)
	service.EXPECT().Token(gomock.Any(), gomock.Any()).Return(nil,
		&types.GoAuthError{Code: services.CodeInvalidClient, Message: "Client authentication failed", StatusCode: http.StatusUnauthorized})

	w := httptest.NewRecorder()
	handler.Token(w, tokenRequest(url.Values{"grant_type": {"authorization_code"}}))
	s.Equal(http.StatusUnauthorized, w.Code)
	s.Contains(w.Header().Get("WWW-Authenticate"), "Basic")
	s.Equal("invalid_client", oauthError(s, w).Error)
}

// The access token is read from the Authorization header or a form body,
// never from the URL.
func (s *IDPHandlerSuite) TestUserInfoBearerToken() {
	form := func(body string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/oidc/userinfo", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	header := func(value string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		req.Header.Set("Authorization", value)
		return req
	}
	cases := map[string]struct {
		req  *http.Request
		want string
	}{
		"header":                 {header("Bearer abc"), "abc"},
		"header, other case":     {header("bearer abc"), "abc"},
		"another scheme":         {header("Basic abc"), ""},
		"bare scheme":            {header("Bearer"), ""},
		"form body":              {form("access_token=abc"), "abc"},
		"query string":           {httptest.NewRequest(http.MethodGet, "/oidc/userinfo?access_token=abc", nil), ""},
		"query string on a post": {httptest.NewRequest(http.MethodPost, "/oidc/userinfo?access_token=abc", nil), ""},
		"nothing":                {httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil), ""},
	}
	for name, tc := range cases {
		s.Run(name, func() {
			handler, service := s.setup(nil)
			service.EXPECT().UserInfo(gomock.Any(), tc.want).Return(map[string]interface{}{"sub": "user-1"}, nil)
			w := httptest.NewRecorder()
			handler.UserInfo(w, tc.req)
			s.Equal(http.StatusOK, w.Code)
			s.Equal("no-store", w.Header().Get("Cache-Control"))
		})
	}
}

func (s *IDPHandlerSuite) TestUserInfoErrorChallenge() {
	handler, service := s.setup(nil)
	service.EXPECT().UserInfo(gomock.Any(), "abc").Return(nil,
		&types.GoAuthError{Code: services.CodeInsufficientScope, Message: "no openid scope", StatusCode: http.StatusForbidden})

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer abc")
	w := httptest.NewRecorder()
	handler.UserInfo(w, req)
	s.Equal(http.StatusForbidden, w.Code)
	s.Equal(`Bearer realm="oidc", error="insufficient_scope"`, w.Header().Get("WWW-Authenticate"))
}

// A request that cannot be answered through the client goes to the host's
// error page when there is one, and is answered in JSON otherwise.
func (s *IDPHandlerSuite) TestAuthorizeErrorPage() {
	failure := &types.GoAuthError{Code: services.CodeInvalidRequest, Message: "redirect_uri is not registered for this client", StatusCode: http.StatusBadRequest}

	handler, service := s.setup(&services.Settings{ErrorURL: "https://app.example.com/oidc/error?lang=en"})
	service.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return("", failure)
	w := httptest.NewRecorder()
	handler.Authorize(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=app", nil))
	s.Equal(http.StatusFound, w.Code)
	location, err := url.Parse(w.Header().Get("Location"))
	s.Require().NoError(err)
	s.Equal("app.example.com", location.Host)
	s.Equal("en", location.Query().Get("lang"), "the page's own query is kept")
	s.Equal("invalid_request", location.Query().Get("error"))
	s.Equal("no-referrer", w.Header().Get("Referrer-Policy"))

	handler, service = s.setup(nil)
	service.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return("", failure)
	w = httptest.NewRecorder()
	handler.Authorize(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=app", nil))
	s.Equal(http.StatusBadRequest, w.Code)
	s.Empty(w.Header().Get("Location"))
	s.Equal("invalid_request", oauthError(s, w).Error)
}

func (s *IDPHandlerSuite) TestPublicDocuments() {
	handler, service := s.setup(nil)
	service.EXPECT().Discovery().Return(dto.DiscoveryDocument{Issuer: "https://api.example.com/auth/oidc"})
	service.EXPECT().JWKS().Return(types.JWKS{})

	w := httptest.NewRecorder()
	handler.Discovery(w, httptest.NewRequest(http.MethodGet, "/oidc/.well-known/openid-configuration", nil))
	s.Equal(http.StatusOK, w.Code)
	s.Equal("application/json", w.Header().Get("Content-Type"))
	s.Equal("*", w.Header().Get("Access-Control-Allow-Origin"), "browser clients read the document from other origins")
	s.Contains(w.Header().Get("Cache-Control"), "public")

	w = httptest.NewRecorder()
	handler.JWKS(w, httptest.NewRequest(http.MethodGet, "/oidc/jwks", nil))
	s.Equal(http.StatusOK, w.Code)
	s.Equal("*", w.Header().Get("Access-Control-Allow-Origin"))
}

// The consent endpoints work from the verified authentication state, not
// from anything the request says about the user.
func (s *IDPHandlerSuite) TestConsentNeedsAPrincipal() {
	handler, _ := s.setup(nil)
	for name, call := range map[string]func(http.ResponseWriter, *http.Request){
		"details": handler.ConsentDetails, "approve": handler.ApproveConsent,
	} {
		w := httptest.NewRecorder()
		call(w, httptest.NewRequest(http.MethodPost, "/oidc/consent/request-1", nil))
		s.Equal(http.StatusUnauthorized, w.Code, name)
	}
}
