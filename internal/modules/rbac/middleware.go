package rbac

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/bete7512/goauth/internal/modules/rbac/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/types"
)

// Actions Resource maps HTTP methods to.
const (
	ActionRead   = "read"
	ActionCreate = "create"
	ActionUpdate = "update"
	ActionDelete = "delete"
)

// Require returns middleware that lets a request through only when the
// caller holds permission. It must run after authentication, for example
// a.RequireAuth(authz.Require("invoice:approve")(handler)).
//
// The permission is declared by being required: nothing has to be listed in
// the configuration. Require panics on a malformed permission, which makes
// a typo in its form show up when routes are wired rather than as a 403.
func (m *RBACModule) Require(permission string, opts ...Option) func(http.Handler) http.Handler {
	m.mustDeclare(permission, "")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.guard(w, r, next, permission, opts)
		})
	}
}

// Resource returns middleware for a group of routes about one resource. It
// picks the permission from the HTTP method: GET and HEAD need
// "<resource>:read", POST "<resource>:create", PUT and PATCH
// "<resource>:update", DELETE "<resource>:delete". OPTIONS passes through
// and any other method is answered with 405.
//
// The method is all it looks at. A route in the group that is not plain
// create, read, update or delete, such as POST /invoices/{id}/approve or
// POST /invoices/search, needs its own Require outside the group.
func (m *RBACModule) Resource(resource string, opts ...Option) func(http.Handler) http.Handler {
	if err := access.ValidateResource(resource); err != nil {
		panic("rbac: " + err.Error())
	}
	for _, action := range []string{ActionRead, ActionCreate, ActionUpdate, ActionDelete} {
		m.mustDeclare(resource+":"+action, "")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var action string
			switch r.Method {
			case http.MethodGet, http.MethodHead:
				action = ActionRead
			case http.MethodPost:
				action = ActionCreate
			case http.MethodPut, http.MethodPatch:
				action = ActionUpdate
			case http.MethodDelete:
				action = ActionDelete
			case http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			default:
				w.Header().Set("Allow", strings.Join([]string{
					http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
					http.MethodPatch, http.MethodDelete, http.MethodOptions,
				}, ", "))
				http_utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
				return
			}
			m.guard(w, r, next, resource+":"+action, opts)
		})
	}
}

// guard decides one request and either passes it on or answers it.
func (m *RBACModule) guard(w http.ResponseWriter, r *http.Request, next http.Handler, permission string, opts []Option) {
	// The memo lets a service called by the handler ask again without a
	// second round of lookups.
	r = r.WithContext(services.WithMemo(r.Context()))
	verdict, authErr := m.evaluate(r.Context(), r, subject{}, permission, opts)
	if authErr != nil {
		if authErr.StatusCode >= http.StatusInternalServerError {
			m.logError("rbac: check failed", authErr, permission)
		}
		status := authErr.StatusCode
		if !validStatus(status) {
			status = http.StatusInternalServerError
		}
		http_utils.RespondError(w, status, string(authErr.Code), authErr.Message)
		return
	}
	if !verdict.Allowed {
		m.deny(w, r, verdict.Check)
		return
	}
	next.ServeHTTP(w, r)
}

// deny answers a refused request: with the application's OnDeny when there
// is one, with a 403 otherwise.
func (m *RBACModule) deny(w http.ResponseWriter, r *http.Request, check access.Check) {
	denied := services.DeniedError(check)
	if m.config.OnDeny == nil {
		http_utils.RespondError(w, denied.StatusCode, string(denied.Code), denied.Message)
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if m.deps.Logger != nil {
				m.deps.Logger.Error("rbac: OnDeny callback panicked", "permission", check.Permission, "panic", fmt.Sprint(recovered))
			}
			http_utils.RespondError(w, denied.StatusCode, string(denied.Code), denied.Message)
		}
	}()
	m.config.OnDeny(w, r, check)
}
