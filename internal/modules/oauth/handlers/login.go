package handlers

import (
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/oauth/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// Login initiates the OAuth login flow for a provider
// GET /oauth/{provider}?redirect_uri=...
func (h *OAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract provider from path
	providerName := extractProviderFromPath(r)
	if providerName == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrOAuthProviderNotFound), "provider is required")
		return
	}

	// Get optional client redirect URI
	clientRedirectURI := r.URL.Query().Get("redirect_uri")

	// Initiate OAuth login
	authURL, authErr := h.service.InitiateLogin(ctx, providerName, clientRedirectURI)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	// Redirect to provider's authorization URL
	http.Redirect(w, r, authURL, http.StatusFound)
}

// ListProviders returns the list of enabled OAuth providers
// GET /oauth/providers
func (h *OAuthHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.service.ListEnabledProviders()

	response := dto.ProvidersResponse{
		Providers: make([]dto.ProviderInfo, 0, len(providers)),
	}

	for _, name := range providers {
		response.Providers = append(response.Providers, dto.ProviderInfo{
			Name:    name,
			Enabled: true,
		})
	}

	http_utils.RespondSuccess(w, response, nil)
}

// LinkedProviders returns the OAuth providers linked to the current user
// GET /oauth/linked
func (h *OAuthHandler) LinkedProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from context (set by auth middleware)
	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "unauthorized")
		return
	}

	providers, authErr := h.service.GetLinkedProviders(ctx, userID)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	if providers == nil {
		providers = []string{}
	}

	http_utils.RespondSuccess(w, dto.LinkedProvidersResponse{Providers: providers}, nil)
}

// Unlink removes an OAuth provider link from the current user
// DELETE /oauth/{provider}
func (h *OAuthHandler) Unlink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract provider from path
	providerName := extractProviderFromPath(r)
	if providerName == "" {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrOAuthProviderNotFound), "provider is required")
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		http_utils.RespondError(w, http.StatusUnauthorized, string(types.ErrUnauthorized), "unauthorized")
		return
	}

	authErr := h.service.UnlinkProvider(ctx, userID, providerName)
	if authErr != nil {
		http_utils.RespondError(w, authErr.StatusCode, string(authErr.Code), authErr.Message)
		return
	}

	http_utils.RespondSuccess(w, map[string]string{
		"message": "provider unlinked successfully",
	}, nil)
}

// extractProviderFromPath extracts the provider name from the URL path
// Supports both /oauth/{provider} and /oauth/{provider}/callback patterns
func extractProviderFromPath(r *http.Request) string {
	path := r.URL.Path

	// Find /oauth/ prefix and extract provider
	idx := strings.Index(path, "/oauth/")
	if idx == -1 {
		return ""
	}

	// Get everything after /oauth/
	remaining := path[idx+7:]
	if remaining == "" {
		return ""
	}

	// Split by / and take the first part
	parts := strings.SplitN(remaining, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}

	// Skip special routes
	provider := parts[0]
	if provider == "providers" || provider == "linked" {
		return ""
	}

	return provider
}
