// Package rbac exposes the role-based access control module.
// Import this package instead of internal/modules/rbac.
//
// The module answers one question, "may this user do this here", on routes
// and in code:
//
//	authz := rbac.New(nil)
//	a.Use(authz)
//
//	mux.Handle("/invoices/", a.RequireAuth(authz.Resource("invoice")(invoices)))
//	mux.Handle("POST /invoices/{id}/approve", a.RequireAuth(authz.Require("invoice:approve")(approve)))
//
//	if err := authz.Check(ctx, "invoice:update", rbac.InOrg(invoice.OrgID)); err != nil { ... }
//
// Permissions have the form "resource:action" and are declared by being
// used. Roles are sets of grants, which may use wildcards ("invoice:*",
// "*:read", "*"). A bare "*" never reaches GoAuth's own "goauth." namespace.
package rbac

import (
	"net/http"

	internal "github.com/bete7512/goauth/internal/modules/rbac"
)

// Module is the rbac module. Register it with Auth.Use and keep the value:
// its methods guard routes (Require, Resource) and decide in code (Can,
// Check, For, Permissions, Assign, Revoke, Define).
type Module = internal.RBACModule

// Config is the configuration for the rbac module.
type Config = internal.Config

// Role is a role defined in code: a key and the grants it carries.
type Role = internal.Role

// ScopeType limits where a role may be assigned.
type ScopeType = internal.ScopeType

// Scopes a Role can be limited to. The zero value allows both.
const (
	// ScopeGlobal is the whole application.
	ScopeGlobal = internal.ScopeGlobal
	// ScopeOrg is one organization.
	ScopeOrg = internal.ScopeOrg
)

// Permissions lists, per resource, the actions the application checks. It is
// only needed with Config.Strict.
type Permissions = internal.Permissions

// PermissionInfo is one entry of the permission catalog.
type PermissionInfo = internal.PermissionInfo

// Authorizer is the interface application code depends on to ask whether
// the caller may do something. *Module and *Subject implement it.
type Authorizer = internal.Authorizer

// Subject decides for one named user instead of the caller in the context.
// Module.For returns one.
type Subject = internal.Subject

// Option adjusts one check: where it runs and any rule of the application's
// own that goes with it.
type Option = internal.Option

// Check describes one authorization decision. Every callback receives it.
type Check = internal.Check

// Condition is a rule of the application's own attached to one check with
// AllowIf or OnlyIf.
type Condition = internal.Condition

// Decision is what a Config.Decide callback returns: Keep, Allow() or
// Deny(reason).
type Decision = internal.Decision

// DecideFunc sees every decision after roles and conditions and may keep,
// allow or deny it.
type DecideFunc = internal.DecideFunc

// Actions that Module.Resource maps HTTP methods to.
const (
	ActionRead   = internal.ActionRead
	ActionCreate = internal.ActionCreate
	ActionUpdate = internal.ActionUpdate
	ActionDelete = internal.ActionDelete
)

// Keep leaves a decision as the roles and conditions reached it.
var Keep = internal.Keep

// New creates the rbac module. Pass nil for the defaults: permissions are
// declared where they are used and roles are application-wide.
func New(cfg *Config) *Module {
	return internal.New(cfg)
}

// Allow grants a request whatever the roles said. Return it from Decide.
func Allow() Decision { return internal.Allow() }

// Deny refuses a request. The reason is returned to the caller. Return it
// from Decide.
func Deny(reason string) Decision { return internal.Deny(reason) }

// Global runs a check against application-wide roles only.
func Global() Option { return internal.Global() }

// InOrg runs a check in the given organization.
func InOrg(orgID string) Option { return internal.InOrg(orgID) }

// OrgParam runs a check in the organization named by a path parameter of
// the route.
func OrgParam(name string) Option { return internal.OrgParam(name) }

// OrgFrom runs a check in the organization fn returns, usually the one that
// owns the resource the request is about. A *types.GoAuthError with an HTTP
// status returned by fn is sent to the client as is; any other error refuses
// the request with 403.
func OrgFrom(fn func(r *http.Request) (string, error)) Option { return internal.OrgFrom(fn) }

// AllowIf lets a request through when fn returns true even if the caller
// lacks the permission.
func AllowIf(fn Condition) Option { return internal.AllowIf(fn) }

// OnlyIf refuses a request when fn returns false even if the caller holds
// the permission.
func OnlyIf(fn Condition) Option { return internal.OnlyIf(fn) }

// Fixed returns an Authorizer that allows exactly the given grants to every
// caller. It is meant for an application's unit tests.
func Fixed(grants ...string) Authorizer { return internal.Fixed(grants...) }
