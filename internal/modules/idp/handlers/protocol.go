package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bete7512/goauth/internal/modules/idp/services"
	"github.com/bete7512/goauth/pkg/types"
)

// Discovery serves the OpenID Provider metadata.
// GET /oidc/.well-known/openid-configuration
func (h *IDPHandler) Discovery(w http.ResponseWriter, _ *http.Request) {
	publicDocument(w, 300)
	_ = json.NewEncoder(w).Encode(h.service.Discovery())
}

// JWKS serves the public keys that verify ID tokens.
// GET /oidc/jwks
func (h *IDPHandler) JWKS(w http.ResponseWriter, _ *http.Request) {
	publicDocument(w, 3600)
	_ = json.NewEncoder(w).Encode(h.service.JWKS())
}

// publicDocument sets the headers of a JSON document that holds nothing
// secret and is the same for every caller. Browser-based clients read these
// documents from other origins, so any origin may, unless the host's own
// CORS middleware already answered.
func publicDocument(w http.ResponseWriter, maxAgeSeconds int) {
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("Cache-Control", "public, max-age="+strconv.Itoa(maxAgeSeconds))
	if header.Get("Access-Control-Allow-Origin") == "" {
		header.Set("Access-Control-Allow-Origin", "*")
	}
}

// Authorize is the authorization endpoint (OpenID Connect Core section
// 3.1.2). It never renders a page: it redirects to the host's consent page,
// or back to the client with an error.
// GET /oidc/authorize
func (h *IDPHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	redirectTo, authErr := h.service.Authorize(r.Context(), r.URL.Query())
	if authErr == nil {
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}
	// The client or its redirect URI could not be verified, so the user is
	// not sent there: show the error on the host's page, or as JSON.
	status, body := h.oauthErrorBody(authErr)
	if h.settings.ErrorURL != "" {
		if target, err := url.Parse(h.settings.ErrorURL); err == nil {
			query := target.Query()
			query.Set("error", body.Error)
			if body.ErrorDescription != "" {
				query.Set("error_description", body.ErrorDescription)
			}
			target.RawQuery = query.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
			return
		}
	}
	writeNoStoreJSON(w, status, body)
}

// Token is the token endpoint (OpenID Connect Core section 3.1.3).
// Parameters are taken from the body only: credentials and tokens must not
// travel in the URL.
// POST /oidc/token
func (h *IDPHandler) Token(w http.ResponseWriter, r *http.Request) {
	if !isMediaType(r, "application/x-www-form-urlencoded") {
		h.writeOAuthError(w, &types.GoAuthError{Code: services.CodeInvalidRequest, Message: "The request body must be application/x-www-form-urlencoded", StatusCode: http.StatusBadRequest})
		return
	}
	if err := r.ParseForm(); err != nil {
		h.writeOAuthError(w, &types.GoAuthError{Code: services.CodeInvalidRequest, Message: "The request body is malformed", StatusCode: http.StatusBadRequest})
		return
	}
	req := &services.TokenRequest{Form: r.PostForm, Metadata: h.requestMetadata(r)}
	if username, password, ok := r.BasicAuth(); ok {
		req.HasBasic = true
		req.BasicID, req.BasicSecret = services.DecodeBasicCredentials(username, password)
	}
	response, authErr := h.service.Token(r.Context(), req)
	if authErr != nil {
		h.writeOAuthError(w, authErr)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, response)
}

// bearerToken extracts the access token of a UserInfo request: from the
// Authorization header, or from the form body of a POST (RFC 6750 sections
// 2.1 and 2.2). A token in the URL is not accepted.
func bearerToken(r *http.Request) string {
	if header := r.Header.Get("Authorization"); header != "" {
		if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
			return strings.TrimSpace(header[7:])
		}
		return ""
	}
	if r.Method == http.MethodPost && isMediaType(r, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err == nil {
			return r.PostForm.Get("access_token")
		}
	}
	return ""
}

// UserInfo is the UserInfo endpoint (OpenID Connect Core section 5.3).
// GET or POST /oidc/userinfo
func (h *IDPHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	claims, authErr := h.service.UserInfo(r.Context(), bearerToken(r))
	if authErr != nil {
		status, body := h.oauthErrorBody(authErr)
		// RFC 6750 section 3: the error travels in the challenge too.
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="`+body.Error+`"`)
		}
		writeNoStoreJSON(w, status, body)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, claims)
}
