package access

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/pkg/types"
)

// ScopeType says where a role applies.
type ScopeType string

// Scopes a role can be held in.
const (
	// ScopeAny is the zero value of Role.Scope: the role may be assigned in
	// any scope.
	ScopeAny ScopeType = ""
	// ScopeGlobal covers the whole application.
	ScopeGlobal ScopeType = "global"
	// ScopeOrg covers one organization.
	ScopeOrg ScopeType = "org"
	// ScopeTeam covers one team and every team beneath it.
	ScopeTeam ScopeType = "team"
)

// Scope is one place a check runs in: the whole application, one
// organization, or one team.
type Scope struct {
	Type ScopeType
	ID   string
	// Org is the organization of a team scope. Callers leave it empty; the
	// services fill it in from the team.
	Org string
}

// GlobalScope is the application-wide scope.
func GlobalScope() Scope { return Scope{Type: ScopeGlobal} }

// OrgScope is the scope of one organization.
func OrgScope(orgID string) Scope { return Scope{Type: ScopeOrg, ID: orgID} }

// TeamScope is the scope of one team.
func TeamScope(teamID string) Scope { return Scope{Type: ScopeTeam, ID: teamID} }

// IsOrg reports whether the scope is an organization.
func (s Scope) IsOrg() bool { return s.Type == ScopeOrg }

// IsTeam reports whether the scope is a team.
func (s Scope) IsTeam() bool { return s.Type == ScopeTeam }

// OrgID returns the organization ID: the organization itself, the team's
// organization once it is known, or "" for the global scope.
func (s Scope) OrgID() string {
	switch s.Type {
	case ScopeOrg:
		return s.ID
	case ScopeTeam:
		return s.Org
	}
	return ""
}

// TeamID returns the team ID, or "" for any other scope.
func (s Scope) TeamID() string {
	if s.Type == ScopeTeam {
		return s.ID
	}
	return ""
}

// Role keys with a fixed meaning.
const (
	// RoleSuperAdmin is held by every user with IsSuperAdmin set. It cannot
	// be assigned, changed or removed through the module.
	RoleSuperAdmin = "super_admin"
	// RoleOwner, RoleAdmin and RoleMember mirror the organization module's
	// membership role. They are implied by membership and never assigned.
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
	// RoleTeamLead and RoleTeamMember mirror the team module's member role,
	// in the team scope: a lead of a team holds RoleTeamLead in it and in
	// every team beneath it. They are implied and never assigned.
	RoleTeamLead   = "lead"
	RoleTeamMember = "member"
)

// Role is a named set of grants defined in code. Roles created at runtime
// are stored in the database instead.
type Role struct {
	// Key identifies the role; lowercase letters, digits, "_" and "-".
	Key string
	// Name and Description are shown in role editors.
	Name        string
	Description string
	// Scope limits where the role may be assigned. The zero value allows
	// both the global scope and organizations.
	Scope ScopeType
	// Grants are patterns such as "invoice:read", "invoice:*", "*:read" or "*".
	Grants []string
}

// AllowedIn reports whether the role may be assigned in scope.
func (r Role) AllowedIn(scope ScopeType) bool {
	return r.Scope == ScopeAny || r.Scope == scope
}

// Check describes one authorization decision. It is passed to every callback.
type Check struct {
	// Principal is the authenticated caller. It is the zero value when the
	// check was made for an explicit user outside a request.
	Principal types.Principal
	// UserID is the user the decision is about.
	UserID string
	// Permission is the permission being checked, for example "invoice:approve".
	Permission string
	// Scope, OrgID and TeamID say where the check runs. OrgID is empty for
	// the global scope; TeamID is set for the team scope, with OrgID its
	// organization.
	Scope  ScopeType
	OrgID  string
	TeamID string
	// Roles are the role keys the user holds in the scope.
	Roles []string
	// Granted is what the roles alone decided, before any callback ran.
	Granted bool
	// Allowed is the decision so far: Granted after the AllowIf and OnlyIf
	// conditions of the check. Decide receives it and may change it.
	Allowed bool
	// Reason explains a denial. It is set by Deny and passed to OnDeny.
	Reason string
	// Request is the HTTP request being guarded, or nil when the check was
	// made from code.
	Request *http.Request
}

// Condition is a rule of the application's own attached to one check.
type Condition func(ctx context.Context, c Check) bool

// Decision is what a Decide callback returns.
type Decision struct {
	effect effect
	reason string
}

type effect int

const (
	effectKeep effect = iota
	effectAllow
	effectDeny
)

// Keep leaves the decision the roles and conditions already reached.
var Keep = Decision{}

// Allow grants the request whatever the roles said.
func Allow() Decision { return Decision{effect: effectAllow} }

// Deny refuses the request. The reason is returned to the caller.
func Deny(reason string) Decision { return Decision{effect: effectDeny, reason: reason} }

// Apply returns the decision after d is applied to allowed, and the reason
// when d denies.
func (d Decision) Apply(allowed bool) (bool, string) {
	switch d.effect {
	case effectAllow:
		return true, ""
	case effectDeny:
		return false, d.reason
	default:
		return allowed, ""
	}
}

// DecideFunc sees every decision and may keep, allow or deny it.
type DecideFunc func(ctx context.Context, c Check) Decision
