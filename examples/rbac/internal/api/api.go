// Package api is the tracker's JSON API. router.go is where authorization
// happens: each route says which permission it needs and where (the whole
// application, an organization, a team). The handlers in the other files
// then only do their job.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bete7512/goauth/examples/rbac/internal/tracker"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/bete7512/goauth/pkg/types"
)

// API serves the tracker's routes.
type API struct {
	store   *tracker.Store
	authz   *rbac.Module
	teamOrg TeamOrgFunc
}

// TeamOrgFunc returns the organization a team belongs to.
type TeamOrgFunc func(ctx context.Context, teamID string) (string, error)

// New creates the API.
func New(store *tracker.Store, authz *rbac.Module, teamOrg TeamOrgFunc) *API {
	return &API{store: store, authz: authz, teamOrg: teamOrg}
}

// caller returns who is making the request. RequireAuth has already
// checked the token, so a principal is always there.
func caller(r *http.Request) types.Principal {
	principal, _ := types.PrincipalFromContext(r.Context())
	return principal
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// writeFailure answers for an error from the store or an in-code check.
func writeFailure(w http.ResponseWriter, err error) {
	var authErr *types.GoAuthError
	switch {
	case errors.Is(err, tracker.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.As(err, &authErr):
		writeError(w, authErr.StatusCode, authErr.Message)
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(into); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}
