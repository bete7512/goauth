package rbac

import (
	"errors"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/pkg/types"
)

// Option adjusts one check: where it runs, and any rule of the application's
// own that goes with it.
type Option func(*checkOptions)

type checkOptions struct {
	scope     *access.Scope
	orgParam  string
	orgFrom   func(r *http.Request) (string, error)
	teamParam string
	teamFrom  func(r *http.Request) (string, error)
	allowIf   []access.Condition
	onlyIf    []access.Condition
}

func collect(opts []Option) checkOptions {
	var o checkOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// Global runs the check against application-wide roles only, whatever
// organization the caller is signed in to.
func Global() Option {
	return func(o *checkOptions) {
		scope := access.GlobalScope()
		o.scope = &scope
	}
}

// InOrg runs the check in the given organization. The caller's roles there
// count, and so do the caller's application-wide roles.
func InOrg(orgID string) Option {
	return func(o *checkOptions) {
		scope := access.OrgScope(orgID)
		o.scope = &scope
	}
}

// OrgParam runs the check in the organization named by a path parameter,
// for routes such as /orgs/{orgId}/invoices. It only works on a route.
func OrgParam(name string) Option {
	return func(o *checkOptions) { o.orgParam = name }
}

// OrgFrom runs the check in the organization fn returns, usually the one
// that owns the resource the request is about. That makes the check answer
// "may the caller do this to this resource", not only "in the caller's own
// organization". It only works on a route; in code use InOrg.
//
// When fn returns a *types.GoAuthError that carries an HTTP status it is sent
// to the client as is, so a missing resource can answer 404. Any other error
// refuses the request with 403.
func OrgFrom(fn func(r *http.Request) (string, error)) Option {
	return func(o *checkOptions) { o.orgFrom = fn }
}

// InTeam runs the check in the given team (rbac Config.Teams). Roles held on
// the team or on any team above it count, and so do the caller's roles in
// the team's organization and application-wide.
func InTeam(teamID string) Option {
	return func(o *checkOptions) {
		scope := access.TeamScope(teamID)
		o.scope = &scope
	}
}

// TeamParam runs the check in the team named by a path parameter, for
// routes such as /teams/{teamId}/projects. It only works on a route.
func TeamParam(name string) Option {
	return func(o *checkOptions) { o.teamParam = name }
}

// TeamFrom runs the check in the team fn returns, usually the one that owns
// the resource the request is about. Errors are handled as for OrgFrom. It
// only works on a route; in code use InTeam.
func TeamFrom(fn func(r *http.Request) (string, error)) Option {
	return func(o *checkOptions) { o.teamFrom = fn }
}

// AllowIf lets a request through when fn returns true even if the caller
// lacks the permission, for rules such as "authors may edit their own".
func AllowIf(fn Condition) Option {
	return func(o *checkOptions) { o.allowIf = append(o.allowIf, fn) }
}

// OnlyIf refuses a request when fn returns false even if the caller holds
// the permission, for rules such as "nobody approves their own invoice".
func OnlyIf(fn Condition) Option {
	return func(o *checkOptions) { o.onlyIf = append(o.onlyIf, fn) }
}

// resolveScope decides where a check runs. An explicit option wins; without
// one the check runs in the organization the caller is signed in to, or
// application-wide when there is none.
func (m *RBACModule) resolveScope(principal types.Principal, r *http.Request, explicitUser bool, o checkOptions) (access.Scope, *types.GoAuthError) {
	switch {
	case o.scope != nil:
		return *o.scope, nil
	case o.orgFrom != nil:
		if r == nil {
			return access.Scope{}, types.NewRBACScopeUnavailableError("OrgFrom needs a request; use InOrg when checking from code")
		}
		orgID, err := o.orgFrom(r)
		if err != nil {
			var authErr *types.GoAuthError
			if errors.As(err, &authErr) && validStatus(authErr.StatusCode) {
				return access.Scope{}, authErr
			}
			return access.Scope{}, types.NewRBACPermissionDeniedError("").Wrap(err)
		}
		return access.OrgScope(orgID), nil
	case o.teamFrom != nil:
		if r == nil {
			return access.Scope{}, types.NewRBACScopeUnavailableError("TeamFrom needs a request; use InTeam when checking from code")
		}
		teamID, err := o.teamFrom(r)
		if err != nil {
			var authErr *types.GoAuthError
			if errors.As(err, &authErr) && validStatus(authErr.StatusCode) {
				return access.Scope{}, authErr
			}
			return access.Scope{}, types.NewRBACPermissionDeniedError("").Wrap(err)
		}
		return access.TeamScope(teamID), nil
	case o.teamParam != "":
		if r == nil {
			return access.Scope{}, types.NewRBACScopeUnavailableError("TeamParam needs a request; use InTeam when checking from code")
		}
		return access.TeamScope(r.PathValue(o.teamParam)), nil
	case o.orgParam != "":
		if r == nil {
			return access.Scope{}, types.NewRBACScopeUnavailableError("OrgParam needs a request; use InOrg when checking from code")
		}
		return access.OrgScope(r.PathValue(o.orgParam)), nil
	case !explicitUser && m.config.Organizations && principal.OrganizationID != "":
		return access.OrgScope(principal.OrganizationID), nil
	default:
		return access.GlobalScope(), nil
	}
}

// validStatus reports whether code can be written as an HTTP error status.
func validStatus(code int) bool {
	return code >= http.StatusBadRequest && code <= 599
}
