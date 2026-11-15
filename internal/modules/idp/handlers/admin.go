package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

func decode[T any](w http.ResponseWriter, r *http.Request) (*T, bool) {
	var body T
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidJSON), "invalid request body")
		return nil, false
	}
	return &body, true
}

// AdminListClients lists registered client applications.
// GET /admin/oidc/clients
func (h *IDPHandler) AdminListClients(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	opts := models.IDPClientListOpts{ListingOpts: http_utils.ParseListingOpts(r), Query: query.Get("q")}
	if managed, err := strconv.ParseBool(query.Get("managed")); err == nil {
		opts.Managed = &managed
	}
	opts.Normalize(100)
	clients, total, authErr := h.service.AdminListClients(r.Context(), opts)
	if authErr != nil {
		h.respondError(w, authErr)
		return
	}
	http_utils.RespondList(w, clients, total, opts.SortField, opts.SortDir)
}

// AdminCreateClient registers a client application. The response carries its
// secret, which is never shown again.
// POST /admin/oidc/clients
func (h *IDPHandler) AdminCreateClient(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[dto.ClientRequest](w, r)
	if !ok {
		return
	}
	client, authErr := h.service.AdminCreateClient(r.Context(), userID(r), req)
	if authErr != nil {
		h.respondError(w, authErr)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http_utils.RespondCreated(w, client, nil)
}

// AdminGetClient returns one client application.
// GET /admin/oidc/clients/{id}
func (h *IDPHandler) AdminGetClient(w http.ResponseWriter, r *http.Request) {
	client, authErr := h.service.AdminGetClient(r.Context(), r.PathValue("id"))
	if authErr != nil {
		h.respondError(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, client, nil)
}

// AdminUpdateClient replaces the registration of a client application.
// PUT /admin/oidc/clients/{id}
func (h *IDPHandler) AdminUpdateClient(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[dto.ClientRequest](w, r)
	if !ok {
		return
	}
	client, authErr := h.service.AdminUpdateClient(r.Context(), userID(r), r.PathValue("id"), req)
	if authErr != nil {
		h.respondError(w, authErr)
		return
	}
	// The response carries a secret when the client stopped being public.
	w.Header().Set("Cache-Control", "no-store")
	http_utils.RespondSuccess(w, client, nil)
}

// AdminDeleteClient removes a client application and disconnects its users.
// DELETE /admin/oidc/clients/{id}
func (h *IDPHandler) AdminDeleteClient(w http.ResponseWriter, r *http.Request) {
	if authErr := h.service.AdminDeleteClient(r.Context(), userID(r), r.PathValue("id")); authErr != nil {
		h.respondError(w, authErr)
		return
	}
	http_utils.RespondSuccess(w, map[string]string{"message": "client application deleted"}, nil)
}

// AdminRotateClientSecret replaces the secret of a client application. The
// response carries the new secret, which is never shown again.
// POST /admin/oidc/clients/{id}/secret
func (h *IDPHandler) AdminRotateClientSecret(w http.ResponseWriter, r *http.Request) {
	client, authErr := h.service.AdminRotateClientSecret(r.Context(), userID(r), r.PathValue("id"))
	if authErr != nil {
		h.respondError(w, authErr)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http_utils.RespondSuccess(w, client, nil)
}
