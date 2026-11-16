package api

import (
	"net/http"
	"strings"

	"github.com/bete7512/goauth/examples/rbac/internal/platform"
	"github.com/bete7512/goauth/pkg/modules/rbac"
)

func (a *API) listTeamProjects(w http.ResponseWriter, r *http.Request) {
	teamID := r.PathValue("teamId")
	orgID, err := a.teamOrg(r.Context(), teamID)
	if err != nil {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.ProjectsOfTeams(orgID, []string{teamID}, false))
}

type projectRequest struct {
	Name string `json:"name"`
}

func (a *API) createProject(w http.ResponseWriter, r *http.Request) {
	var req projectRequest
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	// The guard already checked project:create in this team. The project
	// is filed under the team's organization, whichever one the caller's
	// token is signed in to.
	teamID := r.PathValue("teamId")
	orgID, err := a.teamOrg(r.Context(), teamID)
	if err != nil {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	writeJSON(w, http.StatusCreated, a.store.AddProject(orgID, teamID, req.Name))
}

func (a *API) getProject(w http.ResponseWriter, r *http.Request) {
	p, err := a.store.Project(r.PathValue("id"))
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (a *API) renameProject(w http.ResponseWriter, r *http.Request) {
	var req projectRequest
	if !decode(w, r, &req) {
		return
	}
	p, err := a.store.RenameProject(r.PathValue("id"), req.Name)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// listProjects lists every project the caller may read in their current
// organization. TeamsWhere says where: everywhere (an organization or
// application-wide role) or in some teams (a team role or a lead's place,
// which also covers the teams beneath).
func (a *API) listProjects(w http.ResponseWriter, r *http.Request) {
	orgID := caller(r).OrganizationID
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "sign in to an organization first: POST /auth/org/switch")
		return
	}
	teamIDs, all, err := a.authz.TeamsWhere(r.Context(), orgID, "project:read")
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"all_teams": all, "projects": a.store.ProjectsOfTeams(orgID, teamIDs, all)})
}

// archiveProject decides in code: load the project, then check the
// permission in its team. Useful when the decision needs the loaded
// resource anyway, or lives in a service rather than a route.
func (a *API) archiveProject(w http.ResponseWriter, r *http.Request) {
	p, err := a.store.Project(r.PathValue("id"))
	if err != nil {
		writeFailure(w, err)
		return
	}
	if err := a.authz.Check(r.Context(), platform.PermProjectArchive, rbac.InTeam(p.TeamID)); err != nil {
		writeFailure(w, err)
		return
	}
	archived, err := a.store.ArchiveProject(p.ID)
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, archived)
}
