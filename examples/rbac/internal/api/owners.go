package api

import (
	"errors"
	"net/http"

	"github.com/bete7512/goauth/examples/rbac/internal/tracker"
	"github.com/bete7512/goauth/pkg/types"
)

// Ownership lookups for rbac.OrgFrom and rbac.TeamFrom: given a request
// about one resource, which organization or team owns it. The check then
// answers "may the caller do this to *this* invoice", not merely "may the
// caller do this somewhere".
//
// A missing resource is returned as a GoAuthError with status 404, which
// rbac sends to the client as is; any other error refuses with 403.

func notFound(what string, err error) error {
	if errors.Is(err, tracker.ErrNotFound) {
		return types.NewNotFoundError(what)
	}
	return err
}

func (a *API) invoiceOrg(r *http.Request) (string, error) {
	inv, err := a.store.Invoice(r.PathValue("id"))
	if err != nil {
		return "", notFound("invoice", err)
	}
	return inv.OrgID, nil
}

func (a *API) projectTeam(r *http.Request) (string, error) {
	p, err := a.store.Project(r.PathValue("id"))
	if err != nil {
		return "", notFound("project", err)
	}
	return p.TeamID, nil
}

func (a *API) taskTeam(r *http.Request) (string, error) {
	t, err := a.store.Task(r.PathValue("id"))
	if err != nil {
		return "", notFound("task", err)
	}
	p, err := a.store.Project(t.ProjectID)
	if err != nil {
		return "", notFound("task", err)
	}
	return p.TeamID, nil
}
