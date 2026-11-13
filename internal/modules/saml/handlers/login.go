package handlers

import (
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/modules/saml/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// Login starts SP-initiated SSO.
// GET /saml/{provider}/login?redirect_uri=...
func (h *SAMLHandler) Login(w http.ResponseWriter, r *http.Request) {
	provider := providerFromPath(r)
	if provider == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrSAMLProviderNotFound), "provider is required")
		return
	}
	start, authErr := h.service.InitiateLogin(r.Context(), provider, r.URL.Query().Get("redirect_uri"))
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}
	ttl := h.config.RequestTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	http.SetCookie(w, h.bindingCookie(provider, start.RequestID, int(ttl.Seconds())))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, start.RedirectURL, http.StatusFound)
}

// Metadata serves the SP metadata the IdP imports.
// GET /saml/{provider}/metadata
func (h *SAMLHandler) Metadata(w http.ResponseWriter, r *http.Request) {
	provider := providerFromPath(r)
	if provider == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrSAMLProviderNotFound), "provider is required")
		return
	}
	out, authErr := h.service.Metadata(provider)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// ListProviders returns the configured connections.
// GET /saml/providers
func (h *SAMLHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	names := h.service.ListProviders()
	base := h.deps.Config.APIURL + h.deps.Config.BasePath + "/saml/"
	response := dto.ProvidersResponse{Providers: make([]dto.ProviderInfo, 0, len(names))}
	for _, name := range names {
		response.Providers = append(response.Providers, dto.ProviderInfo{
			Name:        name,
			LoginURL:    base + name + "/login",
			MetadataURL: base + name + "/metadata",
		})
	}
	http_utils.RespondSuccess(w, response, nil)
}
