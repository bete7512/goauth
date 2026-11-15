package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/models"
)

// ConsentDetails describes a pending sign-in request to the consent page.
// GET /oidc/consent/{id}
func (h *IDPHandler) ConsentDetails(w http.ResponseWriter, r *http.Request) {
	user, ok := principal(w, r)
	if !ok {
		return
	}
	details, authErr := h.service.ConsentDetails(r.Context(), user, r.PathValue("id"))
	if authErr != nil {
		h.respondError(w, authErr)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http_utils.RespondSuccess(w, details, nil)
}

// ApproveConsent records the signed-in user's approval and returns the
// redirect that carries the authorization code back to the client.
// POST /oidc/consent/{id}/approve
func (h *IDPHandler) ApproveConsent(w http.ResponseWriter, r *http.Request) {
	user, ok := principal(w, r)
	if !ok {
		return
	}
	redirectTo, authErr := h.service.ApproveConsent(r.Context(), user, r.PathValue("id"), h.requestMetadata(r))
	if authErr != nil {
		h.respondError(w, authErr)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http_utils.RespondSuccess(w, dto.ConsentRedirect{RedirectTo: redirectTo}, nil)
}

// DenyConsent records the refusal and returns the redirect that tells the
// client access was denied.
// POST /oidc/consent/{id}/deny
func (h *IDPHandler) DenyConsent(w http.ResponseWriter, r *http.Request) {
	redirectTo, authErr := h.service.DenyConsent(r.Context(), userID(r), r.PathValue("id"), h.requestMetadata(r))
	if authErr != nil {
		h.respondError(w, authErr)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http_utils.RespondSuccess(w, dto.ConsentRedirect{RedirectTo: redirectTo}, nil)
}

// ListGrants lists the applications the user is connected to.
// GET /oidc/grants
func (h *IDPHandler) ListGrants(w http.ResponseWriter, r *http.Request) {
	opts := models.IDPGrantListOpts{ListingOpts: http_utils.ParseListingOpts(r), ClientID: r.URL.Query().Get("client_id")}
	opts.Normalize(100)
	grants, total, authErr := h.service.ListGrants(r.Context(), userID(r), opts)
	if authErr != nil {
		h.respondError(w, authErr)
		return
	}
	http_utils.RespondList(w, grants, total, opts.SortField, opts.SortDir)
}

// RevokeGrant disconnects one of the user's applications.
// DELETE /oidc/grants/{id}
func (h *IDPHandler) RevokeGrant(w http.ResponseWriter, r *http.Request) {
	if authErr := h.service.RevokeGrant(r.Context(), userID(r), r.PathValue("id"), h.requestMetadata(r)); authErr != nil {
		h.respondError(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, map[string]string{"message": "application disconnected"}, nil)
}
