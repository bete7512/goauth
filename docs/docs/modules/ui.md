---
id: ui
title: UI Module
sidebar_label: UI
sidebar_position: 18
---

# UI Module

The UI module is a server-rendered console. Super admins get an admin console for everything GoAuth manages: users and their sign-in methods, organizations, invitations, roles and permissions, OIDC clients, the audit log and a read-only view of the configuration. Optionally, every user gets a sign-in page and an account page. Pages are plain HTML forms enhanced with [htmx](https://htmx.org), which is embedded, so the console needs no build step, no Node toolchain and nothing loaded from another origin.

:::info Experimental
The module is new. See [Known limitations](#known-limitations) for what is not covered yet.
:::

## Registration

```go
// The admin console only, for super admins.
if err := a.Use(ui.New(nil)); err != nil {
    return err
}
```

```go
// The console at a path of its own: /admin, /admin/login, /admin/users …
if err := a.Use(ui.New(&ui.Config{Path: "/admin"})); err != nil {
    return err
}
```

```go
// The console plus a sign-in and account page for every user.
if err := a.Use(ui.New(&ui.Config{
    UserPages: true,
    Title:     "Acme Cloud",
})); err != nil {
    return err
}
```

Import `pkg/modules/ui`. By default the console is served under `BasePath + "/ui"`, for example `/auth/ui`, with the sign-in page at `/auth/ui/login`. Set `Path` to mount it somewhere of its own instead, such as `/admin`; the JSON API stays under `BasePath`. Either way, register the routes with your router as you do the other routes, for instance with `stdhttp.Register`.

A separate path is usually better. The console serves pages, not API responses, so it does not belong under a versioned API prefix such as `/api/v1`. Gateways and middleware attached to `/api/*` (CORS, JSON error pages, API keys) would otherwise apply to it too.

The module depends only on `core`. Every area is always listed in the sidebar; an area whose module is not registered is shown greyed out, and hovering it names the module to register. Its pages answer with a page saying the same.

| Area | Needs |
| --- | --- |
| Users: profile, create, delete, unlock, set password, sign out everywhere | — |
| Users: password reset and verification emails | `notification` |
| Users: linked accounts | `oauth` or `saml` |
| Users: sessions list | the `session` strategy |
| Users: two-factor status and reset | `twofactor` |
| Users: passkeys | `passkeys` |
| Users: connected applications | `idp` |
| Organizations, members, ownership, organization invitations | `organization` |
| Platform invitations | `invitation` |
| Roles and permissions | `rbac` |
| Organization roles | `rbac` with `Organizations: true`, and `organization` |
| OIDC clients | `idp` |
| Audit log and user activity | `audit` |
| Settings | — |
| Teams | not available yet; the entry is a placeholder until the team module ships |

## Configuration

| Field | Effective behavior |
| --- | --- |
| `Path` | Absolute path to mount the console at, such as `/admin`. Empty serves it at `BasePath + "/ui"`. Must be clean, not `/`, and reachable by the credential cookies: `Initialize` fails if `Security.Session.Path` is narrower, for example `/api/v1` with `Path: "/admin"` |
| `UserPages` | Let users who are not super admins sign in through the console and open `/ui/account`. Default off |
| `Title` | Product name shown in the header and page titles. Default `GoAuth` |
| `PageSize` | Rows per list page. Default 25, at most 100 |
| `TrustedOrigins` | Extra origins, such as `https://admin.example.com`, whose form submissions are accepted. Needed when a proxy rewrites the `Host` header |

The console signs in with the application's own credential cookies, so `Security.AuthMode` must be `cookie` or `both` (the default). `Initialize` fails in bearer-only mode. A user signed in to the console is also signed in to your application in the same browser, because the cookies are the same.

## Who can open what

| Visitor | Admin pages | Account page |
| --- | --- | --- |
| Super admin (`IsSuperAdmin`) | Yes | With `UserPages` |
| Any other user | No (403) | With `UserPages` |
| Not signed in | Sent to sign in | Sent to sign in |

Without `UserPages`, a user who is not a super admin can still submit the sign-in form, but the credentials are revoked at once and the page answers "This console is for administrators". No cookies are set.

## What the console manages

**Users.** Search and page through every account. Create a user with the same password policy and uniqueness rules as signup. Edit profile fields and the active, verified and super admin flags; switching *Active* off bans the account. Each user page has four tabs:

- **Profile:** the form, plus quick actions: send a password reset or verification email, set a temporary password, sign out everywhere, unlock. A locked-out account shows a banner with the failed-attempt count and an *Unlock now* button. GoAuth's lockout is on by default, so this is the most common support case.
- **Security:** linked external accounts (unlink), sessions (end one), two-factor status with backup codes left (reset), passkeys (remove), and applications connected through the identity provider (disconnect).
- **Access:** application-wide roles and organization memberships.
- **Activity:** audit events about the user.

**Organizations.** List and search, create one for an existing user who becomes the owner, rename, suspend or restore, delete (type the slug to confirm). **Members:** add an existing user directly, change between admin and member, remove, and transfer ownership; the previous owner stays as an admin. **Invitations:** see and cancel. **Roles:** with `rbac` and `Organizations: true`, the organization's own roles and each member's roles inside it.

**Invitations.** Every platform invitation from every administrator, filtered by status; send and cancel.

**Roles and permissions.** Create, edit (name, description, grants) and delete custom roles; roles defined in code are read-only. Each role page lists who holds it. The permissions page lists every permission the application has declared, with the roles that grant it.

**OIDC clients.** Create, edit, disable, rotate the secret and delete. A new or rotated secret is shown once. Clients declared in the identity provider's configuration are read-only.

**Audit log.** Filter by action or user, page through, apply the retention periods.

**Settings.** Read-only: strategy, token lifetimes, verification requirements, password and lockout policy, rate limiting, cookie and network settings, and which modules are registered. Settings live in code.

Administrators cannot deactivate, demote, sign out, set the password of, or delete their own account from the console, so that nobody locks themselves out. The JSON admin API does not have this rule.

### Keeping the console complete

Every administrative route must have a console page or a written reason it has none. A route is administrative when its name starts with `admin.` or `rbac.`, contains `.admin.`, or it is guarded by the admin middleware. The mapping lives in `internal/modules/ui/coverage.go`, and `tests/integration/ui_coverage_test.go` fails when a module adds such a route without updating it. Today every administrative route has a page; the only exemption is `GET /me/permissions`, which is self-service.

## Endpoints

There are 67 routes; the full list with their forms is in the [endpoint reference](../api/endpoints.md#ui-module). Paths are relative to the console root: `BasePath + "/ui"` by default, or `Path`. With `Path: "/admin"`, the users page is `/admin/users`.

| Area | Pages |
| --- | --- |
| Sign-in | `/login`, `/login/2fa`, `/logout`, `/account` (with `UserPages`) |
| Overview | `/` (the root itself) |
| Users | `/users`, `/users/new`, `/users/{id}` with `/security`, `/access`, `/activity`, and actions under `/users/{id}/...` |
| Organizations | `/orgs`, `/orgs/new`, `/orgs/{orgId}` with `/members`, `/invitations`, `/roles` |
| Invitations | `/invitations` |
| Roles and permissions | `/roles`, `/roles/{roleKey}`, `/permissions` |
| OIDC clients | `/clients`, `/clients/new`, `/clients/{clientId}` |
| Activity and system | `/audit`, `/settings` |
| Assets | `/assets/{file}` |

The module's OpenAPI document lists no paths, because these are pages rather than an API.

## Flow

1. A visitor opens a console page. Without a valid access cookie the console tries the refresh cookie. If that works it sets new cookies and continues; otherwise it sends the visitor to the sign-in page with `?next=` set.
2. The sign-in form runs the same password check as `POST /login`: lockout, eligibility, `before.login` hooks and completion interceptors.
3. If the user has two-factor authentication, the second step asks for a code and completes the same continuation as `POST /2fa/verify-login`. Other challenges, such as choosing an organization, are not supported; the page says so.
4. On success the console sets the credential cookies and redirects to `next`, if it is a console page the visitor may open, or to their home page.
5. Searching and paging swap only the table. Every other link and form loads a whole page, so the console also works with JavaScript off.
6. Signing out revokes the credentials, as `POST /logout` does, and clears the cookies.

## Security

- **Cross-site requests are refused.** Every route is wrapped in Go's `http.CrossOriginProtection`, which rejects form submissions from another site by their `Sec-Fetch-Site` and `Origin` headers. The CSRF module skips `ui.*` routes for that reason. Credential cookies are also `SameSite=Lax` by default.
- **Content-Security-Policy** allows scripts, styles and requests from the console's own origin only, with no inline script or style. htmx is configured not to evaluate code, not to inject styles and not to keep page snapshots in browser storage.
- **Other headers:** `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store` on every page.
- **Redirects after sign-in** only go to clean paths inside the console.
- **Notices** after an action come from a fixed list. A message is never read from the URL, so a link cannot make the console show text of someone else's choosing.
- **Rate limiting:** the default rate-limit rules cover `ui.login` and `ui.login.2fa` per address and per account. The rate limiter reads the account from form bodies as well as JSON.

## Events and Errors

The console emits no events of its own; the services it calls emit theirs, with the administrator as the actor. User changes made from the console (unlink, end session, reset two-factor, remove passkey, set password, sign out everywhere, unlock) are recorded as `admin.user.updated` with a description; creating a user is `admin.user.created`, deleting one `admin.user.deleted`. Organization changes emit the organization module's events (`org.updated`, `org.deleted`, `org.member.added`, `org.member.removed`, `org.member.role.changed`), so the RBAC module's cleanup runs as it would for an owner's change.

Errors are shown as pages, never as JSON: `422` with the form and a message for a rejected change, `404` for something missing or a module that is not registered, `403` for a visitor who is not a super admin, and `500` for a failed lookup, which is also logged.

## Known Limitations

- **Teams** are not in GoAuth yet; the sidebar entry is a placeholder.
- **Password sign-in only.** OAuth, SAML, magic links and passkeys are not offered on the sign-in page, and choosing an organization during sign-in is not supported.
- **Not yet:** impersonation, bans with a reason and expiry (use *Active*), bulk actions and CSV export, metrics charts, and editing configuration (it lives in code).
- **The account page is read-only.** Profile edits and password changes go through your application or the core endpoints.
- **One shared session.** The console uses the application's cookies, so it lives on the application's origin, at a path those cookies reach.
- **Refresh races are possible.** If several requests arrive at the moment an access token expires, more than one may try to use the same refresh token, and refresh-token rotation may reject the extras. The console makes one request at a time, so this is unlikely.
- **htmx 2.0.7** is vendored; see `internal/modules/ui/assets/THIRD_PARTY_NOTICES.txt`.
