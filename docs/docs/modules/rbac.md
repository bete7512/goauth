---
id: rbac
title: RBAC Module
seoTitle: "RBAC for Go: roles and permissions"
description: "Role-based access control for Go with GoAuth: guard routes with permissions, check them in services, define roles in code or storage, scope them to organizations."
keywords: ["golang rbac", "go roles and permissions", "go authorization library", "permission middleware golang", "casbin alternative"]
sidebar_label: RBAC
sidebar_position: 17
---

# RBAC Module

The RBAC module adds role-based access control to your Go application. It answers one question: may this user do this, here? You guard routes with it, ask it from your services, and let administrators manage roles through the endpoints it ships. Permissions are declared by being used, so there is no list to keep in step with your routes.

:::info Experimental
The module is new. Roles apply application-wide or inside one organization; teams are not supported yet.
:::

## Example

[`examples/rbac`](https://github.com/bete7512/goauth/tree/main/examples/rbac) is a runnable project tracker that uses every guard on this page: application-wide, organization and team roles, `OrgFrom`/`TeamFrom` ownership lookups, `OnlyIf`/`AllowIf` rules, `TeamsWhere` for lists, and checks in code. It ships with a walkthrough script and a test of each scenario.

## Registration

```go
authz := rbac.New(&rbac.Config{
    Roles: []rbac.Role{
        {Key: "viewer", Grants: []string{"*:read"}},
        {Key: "editor", Grants: []string{"*:read", "*:create", "*:update"}},
    },
})
if err := a.Use(authz); err != nil {
    return err
}
```

Import `pkg/modules/rbac`. Keep the value `rbac.New` returns: its methods are the API you call. `rbac.New(nil)` works too; the only role is then the built-in one for super admins, and you add roles at runtime.

The module depends on `core`. With `Organizations: true` it also depends on the `organization` module, and `Initialize` fails when that module is missing.

## Permissions and Grants

A permission is `resource:action`, for example `invoice:approve`. Both parts are lowercase names made of letters, digits, `_`, `-` and `.`.

A role holds **grants**. A grant is a permission or a pattern:

| Grant | Allows |
| --- | --- |
| `invoice:read` | That one permission |
| `invoice:*` | Every action on `invoice` |
| `*:read` | `read` on every resource |
| `billing.*:read` | `read` on every resource under `billing.`, such as `billing.invoice` |
| `*` | Everything in your application |

Grants only allow. There is no deny rule, so "everything except payroll" has to be written as a list.

GoAuth's own permissions live under the reserved `goauth.` namespace: `goauth.roles:read`, `goauth.roles:write`, `goauth.assignments:read` and `goauth.assignments:write`. **A bare `*` never matches them.** A role reaches them only by naming the namespace, as in `goauth.roles:read` or `goauth.*:*`. Your own permissions cannot use the namespace.

## Guarding Routes

Both guards run after authentication, so wrap them in `a.RequireAuth`:

```go
// Create, read, update and delete for a whole resource:
// GET/HEAD need invoice:read, POST invoice:create, PUT/PATCH invoice:update, DELETE invoice:delete.
mux.Handle("/invoices/", a.RequireAuth(authz.Resource("invoice")(invoiceRoutes)))

// Anything else is named where it is used.
mux.Handle("POST /invoices/{id}/approve", a.RequireAuth(authz.Require("invoice:approve")(approve)))
```

`Require` and `Resource` add the permissions they guard to the catalog and **panic on a malformed permission**, so a mistake in its form shows up when routes are wired. `Resource` looks only at the HTTP method: a route in the group that is not plain create, read, update or delete (`POST /invoices/search`, `POST /invoices/{id}/approve`) needs its own `Require` registered outside the group. `OPTIONS` passes through and other methods answer `405`.

A refused request gets `403` with `RBAC_PERMISSION_DENIED`. A request without a signed-in user gets `401`. A lookup that fails answers `500`: an outage is not reported as a refusal.

The guards are `net/http` middleware. They work with the standard mux and chi as they are. With gin or fiber, authenticate, put the principal in the context with `types.WithPrincipal`, and call `Can` or `Check` in the handler.

## Deciding in Code

```go
func (s *ProjectService) Update(ctx context.Context, id string, in UpdateInput) error {
    project, err := s.repo.Get(ctx, id)
    if err != nil {
        return err
    }
    if err := authz.Check(ctx, "project:update", rbac.InOrg(project.OrgID)); err != nil {
        return err // a *types.GoAuthError: 401, 403 or 500
    }
    return s.repo.Update(ctx, project, in)
}
```

| Call | Use |
| --- | --- |
| `authz.Can(ctx, permission, opts...)` | `true` or `false`. False when nobody is signed in or the answer could not be worked out |
| `authz.Check(ctx, permission, opts...)` | `nil`, or a `*types.GoAuthError` saying why |
| `authz.Permissions(ctx, opts...)` | The caller's grants as sorted patterns |
| `authz.For(userID)` | The same three for a named user, for workers, jobs and commands that have no request |
| `authz.Assign(ctx, userID, role, opts...)`, `authz.Revoke(...)` | Change roles from your own code. Trusted: no permission is needed |
| `authz.Define(permission, description)` | Declare a permission that is only checked from code, so the catalog lists it before its first use |

The caller is the `types.Principal` that `RequireAuth` put in the context, so a service only needs the request's context passed down. Depend on the `rbac.Authorizer` interface (`Can`, `Check`) in services; in unit tests pass `rbac.Fixed("invoice:*")`, which allows exactly those grants and does no lookups.

A guard remembers what the caller holds for the rest of the request, so a check made by the service behind a guarded route costs no further lookups.

## Roles

| Role | Held by | Default grants |
| --- | --- | --- |
| `super_admin` | Every user with `IsSuperAdmin` | `*` and `goauth.*:*`, everywhere |
| `owner` | The owner of an organization | `*` and `goauth.*:*` in that organization |
| `admin` | Organization members with the `admin` role | `*`, `goauth.roles:read`, `goauth.assignments:read` |
| `member` | Every other organization member | Nothing |

These four are **implied**: they come from the super admin flag and from organization membership, and are never assigned. The last three exist only with `Organizations: true`. An organization `admin` can do anything in your application but cannot hand out roles; that stays with the owner, as changing member roles does in the organization module.

A plain `member` holds nothing until you say otherwise. To change what a membership role grants, define a role with its key for organizations:

```go
Roles: []rbac.Role{
    {Key: "member", Scope: rbac.ScopeOrg, Grants: []string{"*:read"}},
}
```

Roles in `Config.Roles` are **defined in code**: they can be assigned but not changed through the API. `Scope` limits where a role may be assigned; the zero value allows both the application and organizations. **Custom roles** are created at runtime through the endpoints and belong to the scope they were created in: a custom role of one organization does not exist in another.

A user may hold several roles in a scope. Application-wide roles also apply inside every organization.

## Organizations

```go
authz := rbac.New(&rbac.Config{Organizations: true})
```

Without an option, a check runs in the organization the caller is signed in to (the one chosen through `/org/switch`), or application-wide when there is none. The same route therefore answers differently for a user who is `billing` in one organization and a plain member in another.

:::warning Routes that are not about one organization
An `owner` or `admin` holds `*` inside their own organization, and any user can create an organization. A route that is about the whole platform, such as suspending a tenant, must therefore be guarded with `rbac.Global()`, which counts application-wide roles only:

`authz.Require("tenant:suspend", rbac.Global())`

Without it, the owner of any organization passes the check while signed in to it. If you would rather have nothing granted by default, replace the grants of `owner` and `admin` as shown under [Roles](#roles).
:::

| Option | The check runs |
| --- | --- |
| `rbac.Global()` | Against application-wide roles only |
| `rbac.InOrg(orgID)` | In that organization |
| `rbac.OrgParam("orgId")` | In the organization named by a path parameter (routes only) |
| `rbac.OrgFrom(fn)` | In the organization `fn` returns, usually the one that owns the resource (routes only) |

**Whether a resource belongs to the organization is still your concern** unless you use `OrgFrom` or `InOrg`. A plain `Require("invoice:approve")` answers "may the caller approve invoices in their organization"; it does not know that invoice 7 belongs to another one. `OrgFrom` closes that gap:

```go
ownOrg := rbac.OrgFrom(func(r *http.Request) (string, error) {
    invoice, err := invoices.Get(r.Context(), r.PathValue("id"))
    if err != nil {
        return "", &types.GoAuthError{Code: types.ErrCustom, Message: "Invoice not found", StatusCode: http.StatusNotFound}
    }
    return invoice.OrgID, nil
})
mux.Handle("GET /invoices/{id}", a.RequireAuth(authz.Require("invoice:read", ownOrg)(show)))
```

When the resolver returns a `*types.GoAuthError` that carries an HTTP status it becomes the response, so a missing resource can answer `404`. Any other error refuses the request with `403`.

Organization roles end with the membership. Each assignment records the membership it was made for, so a user who leaves an organization and joins it again starts without the roles held before.

## Teams

With `Teams: true` (which needs `Organizations` and the [team module](./team)), roles can be held inside teams:

```go
authz := rbac.New(&rbac.Config{Organizations: true, Teams: true, Roles: []rbac.Role{
    {Key: "editor", Grants: []string{"project:*"}},
}})
```

- **Roles flow down.** A role held on a team applies to that team and every team beneath it, never above or beside.
- **The organization's roles apply in its teams**, and so do application-wide roles.
- **Implied team roles.** A lead of the team, or of any team above it, holds the built-in `lead` role there, which grants every permission of the application's own (`*`), like an organization admin. A plain member of the team holds `member`, which grants nothing. A role defined in code with key `lead` or `member` and `Scope: rbac.ScopeTeam` replaces what it grants.
- **Teams use the organization's roles.** Custom roles are created per organization and assigned in its teams; roles defined in code with no scope apply to teams too, and `Scope: rbac.ScopeTeam` limits a role to teams. Creating or changing roles in a team scope is refused.
- **Team roles end with the organization membership**, like organization roles.

| Option | The check runs |
| --- | --- |
| `rbac.InTeam(teamID)` | In that team |
| `rbac.TeamParam("teamId")` | In the team named by a path parameter (routes only) |
| `rbac.TeamFrom(fn)` | In the team `fn` returns, usually the one that owns the resource (routes only); errors as for `OrgFrom` |

```go
mux.Handle("DELETE /teams/{teamId}/projects/{id}",
    a.RequireAuth(authz.Require("project:delete", rbac.TeamParam("teamId"))(deleteProject)))
```

A team that does not exist grants nothing beyond application-wide roles.

For routes that list team resources, `TeamsWhere` says where the caller may act:

```go
ids, all, err := authz.TeamsWhere(ctx, orgID, "project:read")
// all: the permission holds in the whole organization; otherwise only in ids.
ids, all, err = authz.For(userID).TeamsWhere(ctx, orgID, "project:read")
```

Each team in `ids` is checked as `InTeam` would, so `AllowIf`-style rules attached to a route are not part of it, but `Decide` is.

## Callbacks

```go
// Must hold the permission AND pass the rule.
authz.Require("invoice:approve", rbac.OnlyIf(func(ctx context.Context, c rbac.Check) bool {
    return invoiceAuthor(c.Request) != c.UserID // nobody approves their own invoice
}))

// Holds the permission OR passes the rule.
authz.Require("invoice:update", rbac.AllowIf(func(ctx context.Context, c rbac.Check) bool {
    return invoiceAuthor(c.Request) == c.UserID // authors edit their own
}))
```

`Config.Decide` sees every decision, from routes and from code, after roles and conditions, and returns `rbac.Keep`, `rbac.Allow()` or `rbac.Deny(reason)`. It is the place for plan limits and feature flags. `Config.OnDeny` writes the response for a refused request instead of the default `403`.

Every callback receives an `rbac.Check`: the principal, the user, the permission, the scope and organization, the roles held, `Granted` (what the roles alone decided), `Allowed` (the decision so far), and the request, which is `nil` when the check came from code. A callback that panics refuses the request.

Rules attached this way are code. They do not appear in `/me/permissions` or in a role editor, so keep them for rules that cannot be expressed as a role.

## Configuration

| Field | Effective behavior |
| --- | --- |
| `Organizations` | Turn on roles inside organizations. Requires the `organization` module. Default off |
| `Teams` | Turn on roles inside teams. Requires `Organizations` and the `team` module. Default off |
| `Roles` | Roles defined in code. A role keyed `owner`, `admin` or `member` that applies to organizations replaces that membership role's grants; a role keyed `lead` or `member` with `ScopeTeam` replaces that team role's grants |
| `Permissions`, `Strict` | A fixed catalog. With `Strict`, a permission that is not listed panics when a route is wired and is refused when checked from code |
| `Decide` | Callback that sees every decision and may keep, allow or deny it |
| `OnDeny` | Callback that writes the response for a refused request |
| `MaxRolesPerScope` | Custom roles per organization, and for the application. Default 100 |
| `MaxGrantsPerRole` | Grants per custom role. Default 100 |
| `MaxRolesPerUser` | Roles assigned to one user in one scope. Default 20 |
| `Storage` | Replaces the storage backend's `RBAC()` store |

Without `Strict`, any well-formed permission is accepted, so a typo such as `invoice:aprove` in `Require` becomes a permission that only wildcard roles hold. Keep permission names in constants, or list them in `Permissions` and set `Strict`.

## Endpoints

All paths are relative to `BasePath` and require authentication. The `/org/{orgId}/...` routes exist only with `Organizations: true`, and the `/org/{orgId}/teams/{teamId}/...` routes only with `Teams: true`.

| Method | Path | Needs | Description |
| --- | --- | --- | --- |
| GET | `/me/permissions` | Signed in | The caller's roles and grants |
| GET | `/rbac/permissions` | `goauth.roles:read` | The permission catalog |
| GET | `/rbac/roles` | `goauth.roles:read` | List application-wide roles |
| POST | `/rbac/roles` | `goauth.roles:write` | Create an application-wide role |
| GET | `/rbac/roles/{roleKey}` | `goauth.roles:read` | Get a role |
| PUT | `/rbac/roles/{roleKey}` | `goauth.roles:write` | Update a custom role |
| DELETE | `/rbac/roles/{roleKey}` | `goauth.roles:write` | Delete a custom role and its assignments |
| GET | `/rbac/users/{userId}/roles` | Self, or `goauth.assignments:read` | A user's application-wide roles |
| PUT | `/rbac/users/{userId}/roles` | `goauth.assignments:write` | Set a user's application-wide roles |
| GET | `/rbac/assignments` | `goauth.assignments:read` | List application-wide assignments |
| GET | `/org/{orgId}/roles` | `goauth.roles:read` | List an organization's roles |
| POST | `/org/{orgId}/roles` | `goauth.roles:write` | Create a role in an organization |
| GET | `/org/{orgId}/roles/{roleKey}` | `goauth.roles:read` | Get a role |
| PUT | `/org/{orgId}/roles/{roleKey}` | `goauth.roles:write` | Update a custom role |
| DELETE | `/org/{orgId}/roles/{roleKey}` | `goauth.roles:write` | Delete a custom role and its assignments |
| GET | `/org/{orgId}/members/{userId}/roles` | Self, or `goauth.assignments:read` | A member's roles |
| PUT | `/org/{orgId}/members/{userId}/roles` | `goauth.assignments:write` | Set a member's roles |
| GET | `/org/{orgId}/role-assignments` | `goauth.assignments:read` | List an organization's assignments |
| GET | `/org/{orgId}/teams/{teamId}/roles` | `goauth.roles:read` | Roles assignable in a team |
| GET | `/org/{orgId}/teams/{teamId}/members/{userId}/roles` | Self, or `goauth.assignments:read` | A user's roles in a team |
| PUT | `/org/{orgId}/teams/{teamId}/members/{userId}/roles` | `goauth.assignments:write` | Set a user's roles in a team |
| GET | `/org/{orgId}/teams/{teamId}/role-assignments` | `goauth.assignments:read` | List a team's assignments |

The permission must be held in the scope being managed: in the team for the team routes, in the organization for the other `/org/...` routes, application-wide for the rest. A team named under another organization's path is not found. Role and assignment lists accept `offset`, `limit`, `sort_field` and `sort_dir`. Roles sort by `created_at`, `key` or `name`; assignments by `created_at`, `role_key` or `user_id`.

**Nobody manages more than they hold.** Creating, changing or deleting a role, and giving or taking one away, requires that every grant of that role is within the caller's own grants. A delegate who holds `goauth.roles:write` and `invoice:read` can create a role with `invoice:read` but not one with `invoice:*`.

The TypeScript client exports `can(grants, permission)`, which matches the grants from `/me/permissions` the way the server does.

## Flow

1. `Require`, `Resource` and `Define` add permissions to the catalog as your routes are wired.
2. A request is authenticated; the principal names the user and, when one was chosen, the organization.
3. The module resolves the scope: an explicit option, else the caller's organization, else the application.
4. It loads what the user holds there: the super admin role, the membership role, and the assigned roles, application-wide and in the organization. A user who does not exist or is not active holds nothing.
5. The grants decide. `AllowIf` and `OnlyIf` conditions adjust the decision, then `Decide`.
6. The request continues, or is answered with `403` or by `OnDeny`.

Nothing is cached between requests and permissions are never written into tokens, so a change to a role or an assignment applies to the next request, on every instance. A check costs two lookups application-wide and three inside the caller's organization, plus one for each scope in which the user holds custom roles, plus one when the organization is not the one the caller is signed in to.

## Events and Errors

| Event | When | Data |
| --- | --- | --- |
| `EventBeforeRBACRoleAssign` | Before a role is given, synchronously. A subscriber that returns an error refuses the change | `*types.RBACAssignmentEventData` |
| `EventRBACRoleAssigned`, `EventRBACRoleRevoked` | After a role was given or taken away | `*types.RBACAssignmentEventData` |
| `EventRBACRoleCreated`, `EventRBACRoleUpdated`, `EventRBACRoleDeleted` | After a custom role changed | `*types.RBACRoleEventData` |

A refusal from `EventBeforeRBACRoleAssign` reaches the caller as `RBAC_ASSIGNMENT_REFUSED` with the subscriber's message, or as the subscriber's own `*types.GoAuthError`.

The module removes assignments when an administrator deletes a user, when a member is removed from an organization and when an organization is deleted. This is housekeeping: a check never relies on it.

| Code | Status | Meaning |
| --- | --- | --- |
| `RBAC_PERMISSION_DENIED` | 403 | The caller lacks the permission, or a callback refused |
| `RBAC_ROLE_NOT_FOUND` | 404 | No role with that key in the scope |
| `RBAC_ROLE_EXISTS` | 409 | The scope already has a role with that key |
| `RBAC_ROLE_SYSTEM` | 409 | The role is defined in code or implied, so it cannot be changed, deleted or assigned |
| `RBAC_INVALID_ROLE` | 400 | Malformed key, name or grant |
| `RBAC_GRANT_NOT_HELD` | 403 | The role grants more than the caller holds |
| `RBAC_LIMIT_EXCEEDED` | 422 | A limit on roles, grants or assignments was reached |
| `RBAC_SCOPE_UNAVAILABLE` | 400 | The scope is not available, such as an organization when `Organizations` is off, a team when `Teams` is off, or creating a role in a team |
| `RBAC_ASSIGNMENT_REFUSED` | 403 | A subscriber refused the assignment |

## Storage

Custom roles are rows in `rbac_roles`; assignments are rows in `rbac_role_assignments`, which name the role by key because roles defined in code have no row. The organization module's `organization_members.role` column is read, never written. A custom backend implements `types.RBACStorage` and returns it from `Storage.RBAC()`, or you pass one in `Config.Storage`.

## Known Limitations

- **Teams have no roles of their own.** They use the organization's custom roles and roles defined in code.
- **`TeamsWhere` scans at most 1,000 teams** of an organization.
- **Allow only.** There are no deny rules.
- **Callbacks are invisible to clients.** `/me/permissions` reports roles and grants, not `AllowIf`, `OnlyIf` or `Decide`.
- **`Resource` looks only at the HTTP method.**
- **Custom role grants are not checked against the catalog**, which may be incomplete; a mistyped grant in a custom role is accepted.
- **First-party users only.** Tokens issued by the identity provider module to other applications carry no principal, so roles do not limit them.
- **The organization module's own endpoints are unchanged.** They still decide by `owner`, `admin` and `member`.
