// Package handlers exposes the idp module over HTTP. The OpenID Connect
// protocol endpoints (discovery, jwks, authorize, token, userinfo) speak the
// wire formats of their specifications; the consent, grant and admin
// endpoints use GoAuth's response envelope.
package handlers

import (
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/idp/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/internal/websession"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// IDPHandler handles the identity provider's HTTP requests.
type IDPHandler struct {
	service  services.IDPService
	deps     config.ModuleDependencies
	settings *services.Settings
	trusted  []net.IPNet
	// sessions and protect serve the module's own page: who is signed in,
	// and the refusal of form posts made by another site.
	sessions *websession.Reader
	protect  *http.CrossOriginProtection
}

// NewIDPHandler creates the handler.
func NewIDPHandler(service services.IDPService, deps config.ModuleDependencies, settings *services.Settings) *IDPHandler {
	trusted, _ := http_utils.ParseCIDRs(deps.Config.TrustedProxies)
	h := &IDPHandler{service: service, deps: deps, settings: settings, trusted: trusted, sessions: websession.New(deps)}
	h.protect = newPageProtection(deps, settings.Issuer, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.pageProblem(w, http.StatusForbidden, "This request was refused", "It came from another site. Go back to the application and sign in again.")
	}))
	return h
}

// GetRoutes returns the routes enabled by the module configuration.
func (h *IDPHandler) GetRoutes() []config.RouteInfo {
	auth := []types.MiddlewareName{types.MiddlewareAuth}
	routes := []config.RouteInfo{
		{Name: string(types.RouteIDPDiscovery), Path: "/oidc/.well-known/openid-configuration", Method: http.MethodGet, Handler: h.Discovery},
		{Name: string(types.RouteIDPJWKS), Path: "/oidc/jwks", Method: http.MethodGet, Handler: h.JWKS},
		{Name: string(types.RouteIDPAuthorize), Path: "/oidc/authorize", Method: http.MethodGet, Handler: h.Authorize},
		{Name: string(types.RouteIDPToken), Path: "/oidc/token", Method: http.MethodPost, Handler: h.Token},
		{Name: string(types.RouteIDPUserInfo), Path: "/oidc/userinfo", Method: http.MethodGet, Handler: h.UserInfo},
		{Name: string(types.RouteIDPUserInfoPost), Path: "/oidc/userinfo", Method: http.MethodPost, Handler: h.UserInfo},
		{Name: string(types.RouteIDPConsentGet), Path: "/oidc/consent/{id}", Method: http.MethodGet, Handler: h.ConsentDetails, Middlewares: auth},
		{Name: string(types.RouteIDPConsentApprove), Path: "/oidc/consent/{id}/approve", Method: http.MethodPost, Handler: h.ApproveConsent, Middlewares: auth},
		{Name: string(types.RouteIDPConsentDeny), Path: "/oidc/consent/{id}/deny", Method: http.MethodPost, Handler: h.DenyConsent, Middlewares: auth},
		{Name: string(types.RouteIDPGrantsList), Path: "/oidc/grants", Method: http.MethodGet, Handler: h.ListGrants, Middlewares: auth},
		{Name: string(types.RouteIDPGrantsRevoke), Path: "/oidc/grants/{id}", Method: http.MethodDelete, Handler: h.RevokeGrant, Middlewares: auth},
	}
	if h.settings.BuiltInPage {
		routes = append(routes, h.pageRoutes()...)
	}
	if h.settings.AdminAPI {
		admin := []types.MiddlewareName{types.MiddlewareAuth, types.MiddlewareAdminAuth}
		routes = append(routes,
			config.RouteInfo{Name: string(types.RouteIDPAdminClientsList), Path: "/admin/oidc/clients", Method: http.MethodGet, Handler: h.AdminListClients, Middlewares: admin},
			config.RouteInfo{Name: string(types.RouteIDPAdminClientsCreate), Path: "/admin/oidc/clients", Method: http.MethodPost, Handler: h.AdminCreateClient, Middlewares: admin},
			config.RouteInfo{Name: string(types.RouteIDPAdminClientsGet), Path: "/admin/oidc/clients/{id}", Method: http.MethodGet, Handler: h.AdminGetClient, Middlewares: admin},
			config.RouteInfo{Name: string(types.RouteIDPAdminClientsUpdate), Path: "/admin/oidc/clients/{id}", Method: http.MethodPut, Handler: h.AdminUpdateClient, Middlewares: admin},
			config.RouteInfo{Name: string(types.RouteIDPAdminClientsDelete), Path: "/admin/oidc/clients/{id}", Method: http.MethodDelete, Handler: h.AdminDeleteClient, Middlewares: admin},
			config.RouteInfo{Name: string(types.RouteIDPAdminClientsSecret), Path: "/admin/oidc/clients/{id}/secret", Method: http.MethodPost, Handler: h.AdminRotateClientSecret, Middlewares: admin},
		)
	}
	return routes
}

// requestMetadata collects where a request came from, for events.
func (h *IDPHandler) requestMetadata(r *http.Request) *types.RequestMetadata {
	return &types.RequestMetadata{
		IPAddress:    http_utils.ClientIP(r, h.trusted),
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		UserAgent:    r.UserAgent(),
		Referer:      r.Referer(),
		Host:         r.Host,
		Timestamp:    time.Now(),
	}
}

// oauthErrorCodes are the error values a client may be sent. Anything else a
// service returns is an internal code and becomes server_error.
var oauthErrorCodes = map[types.ErrorCode]bool{
	services.CodeInvalidRequest: true, services.CodeInvalidClient: true, services.CodeInvalidGrant: true,
	services.CodeUnauthorizedClient: true, services.CodeUnsupportedGrantType: true, services.CodeUnsupportedResponseType: true,
	services.CodeInvalidScope: true, services.CodeAccessDenied: true, services.CodeServerError: true,
	services.CodeInvalidToken: true, services.CodeInsufficientScope: true, services.CodeInteractionRequired: true,
	services.CodeRequestNotSupported: true, services.CodeRequestURINotSupported: true,
}

// oauthErrorBody converts a service error to the RFC 6749 error object and
// logs the cause of internal failures, which is never sent to the client.
func (h *IDPHandler) oauthErrorBody(authErr *types.GoAuthError) (int, dto.OAuthError) {
	status, body := authErr.StatusCode, dto.OAuthError{Error: string(authErr.Code), ErrorDescription: authErr.Message}
	if !oauthErrorCodes[authErr.Code] {
		status, body = http.StatusInternalServerError, dto.OAuthError{Error: string(services.CodeServerError)}
	}
	if status == 0 {
		status = http.StatusBadRequest
	}
	if status >= http.StatusInternalServerError {
		h.deps.Logger.Errorf("idp: %s: %v", authErr.Message, authErr.Err)
		body.ErrorDescription = "The server encountered an unexpected error"
	}
	return status, body
}

// writeOAuthError writes an RFC 6749 section 5.2 error response.
func (h *IDPHandler) writeOAuthError(w http.ResponseWriter, authErr *types.GoAuthError) {
	status, body := h.oauthErrorBody(authErr)
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc", charset="UTF-8"`)
	}
	writeNoStoreJSON(w, status, body)
}

// writeNoStoreJSON writes a JSON response that must not be cached, as
// RFC 6749 section 5.1 requires for anything carrying tokens.
func writeNoStoreJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// respondError writes a GoAuth envelope error and logs internal failures.
func (h *IDPHandler) respondError(w http.ResponseWriter, authErr *types.GoAuthError) {
	if authErr.StatusCode >= http.StatusInternalServerError {
		h.deps.Logger.Errorf("idp: %s: %v", authErr.Message, authErr.Err)
	}
	http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
}

// isMediaType reports whether the request body is of the given media type.
func isMediaType(r *http.Request, want string) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == want
}

// userID returns the authenticated user set by the auth middleware.
func userID(r *http.Request) string {
	id, _ := r.Context().Value(types.UserIDKey).(string)
	return id
}

// principal returns the verified authentication state of the request. The
// authentication middleware sets it; a request without one is refused.
func principal(w http.ResponseWriter, r *http.Request) (types.Principal, bool) {
	p, ok := types.PrincipalFromContext(r.Context())
	if !ok || p.UserID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "authentication required")
		return types.Principal{}, false
	}
	return p, true
}
