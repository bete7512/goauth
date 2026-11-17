---
id: ui
title: UI Module
seoTitle: "Go admin dashboard and login pages, no JavaScript build"
description: "A server-rendered admin console and sign-in pages for Go with GoAuth: manage users, bans, organizations, roles, OIDC clients and audit logs. htmx, no Node build."
keywords: ["golang admin dashboard", "go user management ui", "go login page", "htmx admin panel", "self-hosted auth dashboard"]
sidebar_label: UI
sidebar_position: 18
---

# UI Module

The UI module is a server-rendered admin dashboard and set of login pages for your Go application. Super admins get an admin console for everything GoAuth manages: users and their sign-in methods, bans, organizations and their teams, invitations (one at a time or imported from CSV), roles and permissions, OIDC clients, the audit log, activity charts and a read-only view of the configuration. Everyone it admits gets an account page, and the sign-in page offers every method the registered modules provide. Pages are plain HTML forms enhanced with [htmx](https://htmx.org), which is embedded, so the console needs no build step, no Node toolchain and nothing loaded from another origin.

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
| Users: profile, create, delete, unlock, set password, sign out everywhere, ban, bulk actions, CSV export | — |
| Users: password reset and verification emails | `notification` |
| Users: linked accounts | `oauth` or `saml` |
| Users: sessions list | the `session` strategy |
| Users: two-factor status and reset | `twofactor` |
| Users: passkeys | `passkeys` |
| Users: connected applications | `idp` |
| Organizations, members, ownership, organization invitations (send, CSV import, cancel), CSV export | `organization` |
| Teams | `team` (and `organization`) |
| Team roles | `rbac` with `Organizations` and `Teams` |
| Platform invitations (send, CSV import, cancel) | `invitation` |
| Roles and permissions | `rbac` |
| Organization roles | `rbac` with `Organizations: true`, and `organization` |
| OIDC clients | `idp` |
| Audit log, user activity, CSV export | `audit` |
| Overview charts: sign-ups | a user store implementing `models.UserSignupCounter` (the GORM store does) |
| Overview charts: sign-ins and failed sign-ins | `audit`, with an audit store implementing `models.AuditActionCounter` |
| Settings | — |
| Sign-in with passkeys | `passkeys`, with the console's origin in `RPOrigins` |
| Sign-in with OAuth or SAML | `oauth` or `saml` |
| Sign-in with an emailed code | `magiclink` with `DeliveryMode` `code` or `both` (and `notification` to send it) |

## Configuration

| Field | Effective behavior |
| --- | --- |
| `Path` | Absolute path to mount the console at, such as `/admin`. Empty serves it at `BasePath + "/ui"`. Must be clean, not `/`, and reachable by the credential cookies: `Initialize` fails if `Security.Session.Path` is narrower, for example `/api/v1` with `Path: "/admin"` |
| `UserPages` | Let users who are not super admins sign in through the console and open the account page. Super admins always have it. Default off |
| `Title` | Product name shown in the header and page titles. Default `GoAuth` |
| `PageSize` | Rows per list page. Default 25, at most 100 |
| `TrustedOrigins` | Extra origins, such as `https://admin.example.com`, whose form submissions are accepted. Needed when a proxy rewrites the `Host` header |

The console signs in with the application's own credential cookies, so `Security.AuthMode` must be `cookie` or `both` (the default). `Initialize` fails in bearer-only mode. A user signed in to the console is also signed in to your application in the same browser, because the cookies are the same.

## Who can open what

| Visitor | Admin pages | Account page |
| --- | --- | --- |
| Super admin (`IsSuperAdmin`) | Yes | Yes |
| Any other user | No (403) | With `UserPages` |
| Not signed in | Sent to sign in | Sent to sign in |

Without `UserPages`, a user who is not a super admin can still submit the sign-in form (by any method), but the credentials are revoked at once and the page answers "This console is for administrators". No cookies are set. Someone already signed in to your application holds cookies that reach the console too; the account page refuses them without `UserPages`.

## What the console manages

**Users.** Search and page through every account. Tick users on the list to deactivate, activate, sign out or delete them together (at most 100; your own account is skipped), or download the list, filtered by the search, as CSV. Create a user with the same password policy and uniqueness rules as signup. Edit profile fields and the active, verified and super admin flags. **Ban** a user with a reason (kept for administrators, not shown to the user) for an hour, a day, 7 or 30 days, or until lifted: the user is signed out everywhere and cannot sign in until the ban ends or is lifted; a banned user shows a banner with a *Lift ban* button and a *Banned* badge in lists. Each user page has four tabs:

- **Profile:** the form, plus quick actions: send a password reset or verification email, set a temporary password, sign out everywhere, unlock. A locked-out account shows a banner with the failed-attempt count and an *Unlock now* button. GoAuth's lockout is on by default, so this is the most common support case.
- **Security:** linked external accounts (unlink), sessions (end one), two-factor status with backup codes left (reset), passkeys (remove), and applications connected through the identity provider (disconnect).
- **Access:** application-wide roles and organization memberships.
- **Activity:** audit events about the user.

**Organizations.** List and search, create one for an existing user who becomes the owner, rename, suspend or restore, delete (type the slug to confirm). **Members:** add an existing user directly, change between admin and member, remove, and transfer ownership; the previous owner stays as an admin. **Invitations:** send one (as member or admin), import a list, see and cancel. **Teams:** see below. **Roles:** with `rbac` and `Organizations: true`, the organization's own roles and each member's roles inside it.

**Teams.** With the [team module](./team), every organization has a Teams tab, and the sidebar's Teams page lists organizations to pick from. See the tree, create teams at the top or beneath another, rename, move (with everything beneath), delete a team with nothing beneath it, add members of the organization as lead or member, change their role, remove them, and, with rbac `Teams` on, set each member's roles inside the team.

**Invitations.** Every platform invitation from every administrator, filtered by status; send, import and cancel.

**Importing invitations.** The platform and organization invitation pages take a CSV file or a pasted list, at most 200 rows and 256 KiB: one address per line, optionally followed by a comma and a purpose (platform) or a role (`admin` or `member`, organization). A first line starting with `email` is skipped and repeated addresses are reported. Every row goes through the same rules as a single invitation, so an address already invited (for the same purpose), an existing member or a malformed address is skipped with the reason, without stopping the others. The result page lists every row.

**Exports.** Users, organizations and the audit log download as CSV, following the page's search or filters. A cell that would start a spreadsheet formula (`=`, `+`, `-`, `@`, tab, carriage return) gets a leading quote.

**Overview.** Totals, the newest users, recent events and three bar charts of the last 30 days: sign-ups, sign-ins and failed sign-ins, drawn on the server as SVG (each bar names its day and count on hover, and each chart has a table view). A chart appears only when its store can count per day.

**Your account.** Change your display name and phone number (a new phone number signs you out everywhere, as core does), change your password (which signs you out everywhere, here included), end your other sessions, remove passkeys and disconnect applications, and see recent activity. Super admins always have it; other users with `UserPages`.

**Roles and permissions.** Create, edit (name, description, grants) and delete custom roles; roles defined in code are read-only. Each role page lists who holds it. The permissions page lists every permission the application has declared, with the roles that grant it.

**OIDC clients.** Create, edit, disable, rotate the secret and delete. A new or rotated secret is shown once. Clients declared in the identity provider's configuration are read-only.

**Audit log.** Filter by action or user, page through, apply the retention periods.

**Settings.** Read-only: strategy, token lifetimes, verification requirements, password and lockout policy, rate limiting, cookie and network settings, and which modules are registered. Settings live in code.

Administrators cannot deactivate, demote, ban, sign out, set the password of, or delete their own account from the admin pages, so that nobody locks themselves out; they change their own password on the account page. The JSON admin API does not have this rule.

### Keeping the console complete

Every administrative route must have a console page or a written reason it has none. A route is administrative when its name starts with `admin.` or `rbac.`, contains `.admin.`, or it is guarded by the admin middleware. The mapping lives in `internal/modules/ui/coverage.go`, and `tests/integration/ui_coverage_test.go` fails when a module adds such a route without updating it. Today every administrative route has a page, the team role routes included; the only exemption is `GET /me/permissions`, which is self-service.

## Endpoints

There are 98 routes; the [endpoint reference](../api/endpoints.md#ui-module) describes their forms. Paths are relative to the console root: `BasePath + "/ui"` by default, or `Path`. With `Path: "/admin"`, the users page is `/admin/users`. Routes for a module that is not registered still exist and answer with a page naming the module.

| Method | Path | Route name |
| --- | --- | --- |
| GET | `/assets/{file}` | `ui.asset` |
| GET | `/` | `ui.home` |
| GET | `/login` | `ui.login.page` |
| POST | `/login` | `ui.login` |
| POST | `/login/2fa` | `ui.login.2fa` |
| GET | `/login/done` | `ui.login.done` |
| POST | `/login/code` | `ui.login.code` |
| POST | `/login/code/verify` | `ui.login.code.verify` |
| POST | `/login/passkey/begin` | `ui.login.passkey.begin` |
| POST | `/login/passkey/finish` | `ui.login.passkey.finish` |
| POST | `/logout` | `ui.logout` |
| GET | `/users` | `ui.users` |
| GET | `/users/new` | `ui.users.new` |
| POST | `/users/bulk` | `ui.users.bulk` |
| GET | `/users/export.csv` | `ui.users.export` |
| POST | `/users` | `ui.users.create` |
| GET | `/users/{id}` | `ui.user` |
| POST | `/users/{id}` | `ui.user.update` |
| POST | `/users/{id}/delete` | `ui.user.delete` |
| GET | `/users/{id}/security` | `ui.user.security` |
| POST | `/users/{id}/unlock` | `ui.user.unlock` |
| POST | `/users/{id}/ban` | `ui.user.ban` |
| POST | `/users/{id}/unban` | `ui.user.unban` |
| POST | `/users/{id}/sign-out` | `ui.user.sign_out` |
| POST | `/users/{id}/password` | `ui.user.password` |
| POST | `/users/{id}/reset-email` | `ui.user.reset_email` |
| POST | `/users/{id}/verification-email` | `ui.user.verification_email` |
| POST | `/users/{id}/accounts/{accountId}/unlink` | `ui.user.accounts.unlink` |
| POST | `/users/{id}/sessions/{sessionId}/revoke` | `ui.user.sessions.revoke` |
| POST | `/users/{id}/2fa/reset` | `ui.user.2fa.reset` |
| POST | `/users/{id}/passkeys/{passkeyId}/delete` | `ui.user.passkeys.delete` |
| POST | `/users/{id}/apps/{grantId}/revoke` | `ui.user.apps.revoke` |
| GET | `/users/{id}/access` | `ui.user.access` |
| POST | `/users/{id}/roles` | `ui.user.roles` |
| GET | `/users/{id}/activity` | `ui.user.activity` |
| GET | `/orgs` | `ui.orgs` |
| GET | `/orgs/new` | `ui.orgs.new` |
| GET | `/orgs/export.csv` | `ui.orgs.export` |
| POST | `/orgs` | `ui.orgs.create` |
| GET | `/orgs/{orgId}` | `ui.org` |
| POST | `/orgs/{orgId}` | `ui.org.update` |
| POST | `/orgs/{orgId}/status` | `ui.org.status` |
| POST | `/orgs/{orgId}/delete` | `ui.org.delete` |
| POST | `/orgs/{orgId}/owner` | `ui.org.owner` |
| GET | `/orgs/{orgId}/members` | `ui.org.members` |
| POST | `/orgs/{orgId}/members` | `ui.org.members.add` |
| GET | `/orgs/{orgId}/members/{userId}` | `ui.org.member` |
| POST | `/orgs/{orgId}/members/{userId}/role` | `ui.org.member.role` |
| POST | `/orgs/{orgId}/members/{userId}/remove` | `ui.org.member.remove` |
| POST | `/orgs/{orgId}/members/{userId}/roles` | `ui.org.member.roles` |
| GET | `/orgs/{orgId}/invitations` | `ui.org.invitations` |
| POST | `/orgs/{orgId}/invitations` | `ui.org.invitations.send` |
| POST | `/orgs/{orgId}/invitations/import` | `ui.org.invitations.import` |
| POST | `/orgs/{orgId}/invitations/{invId}/cancel` | `ui.org.invitations.cancel` |
| GET | `/orgs/{orgId}/roles` | `ui.org.roles` |
| POST | `/orgs/{orgId}/roles` | `ui.org.roles.create` |
| GET | `/orgs/{orgId}/roles/{roleKey}` | `ui.org.role` |
| POST | `/orgs/{orgId}/roles/{roleKey}` | `ui.org.role.update` |
| POST | `/orgs/{orgId}/roles/{roleKey}/delete` | `ui.org.role.delete` |
| GET | `/teams` | `ui.teams` |
| GET | `/orgs/{orgId}/teams` | `ui.org.teams` |
| POST | `/orgs/{orgId}/teams` | `ui.org.teams.create` |
| GET | `/orgs/{orgId}/teams/{teamId}` | `ui.team` |
| POST | `/orgs/{orgId}/teams/{teamId}` | `ui.team.update` |
| POST | `/orgs/{orgId}/teams/{teamId}/move` | `ui.team.move` |
| POST | `/orgs/{orgId}/teams/{teamId}/delete` | `ui.team.delete` |
| POST | `/orgs/{orgId}/teams/{teamId}/members` | `ui.team.members.add` |
| GET | `/orgs/{orgId}/teams/{teamId}/members/{userId}` | `ui.team.member` |
| POST | `/orgs/{orgId}/teams/{teamId}/members/{userId}/role` | `ui.team.members.role` |
| POST | `/orgs/{orgId}/teams/{teamId}/members/{userId}/remove` | `ui.team.members.remove` |
| POST | `/orgs/{orgId}/teams/{teamId}/members/{userId}/roles` | `ui.team.member.roles` |
| GET | `/invitations` | `ui.invitations` |
| POST | `/invitations` | `ui.invitations.send` |
| POST | `/invitations/import` | `ui.invitations.import` |
| POST | `/invitations/{invId}/cancel` | `ui.invitations.cancel` |
| GET | `/roles` | `ui.roles` |
| POST | `/roles` | `ui.roles.create` |
| GET | `/roles/{roleKey}` | `ui.role` |
| POST | `/roles/{roleKey}` | `ui.role.update` |
| POST | `/roles/{roleKey}/delete` | `ui.role.delete` |
| GET | `/permissions` | `ui.permissions` |
| GET | `/clients` | `ui.clients` |
| GET | `/clients/new` | `ui.clients.new` |
| POST | `/clients` | `ui.clients.create` |
| GET | `/clients/{clientId}` | `ui.client` |
| POST | `/clients/{clientId}` | `ui.client.update` |
| POST | `/clients/{clientId}/rotate` | `ui.client.rotate` |
| POST | `/clients/{clientId}/delete` | `ui.client.delete` |
| GET | `/audit` | `ui.audit` |
| POST | `/audit/cleanup` | `ui.audit.cleanup` |
| GET | `/audit/export.csv` | `ui.audit.export` |
| GET | `/settings` | `ui.settings` |
| GET | `/account` | `ui.account` |
| POST | `/account` | `ui.account.update` |
| POST | `/account/password` | `ui.account.password` |
| POST | `/account/sessions/{sessionId}/revoke` | `ui.account.sessions.revoke` |
| POST | `/account/passkeys/{passkeyId}/delete` | `ui.account.passkeys.delete` |
| POST | `/account/apps/{grantId}/revoke` | `ui.account.apps.revoke` |

The module's OpenAPI document lists no paths, because these are pages rather than an API.

## Flow

1. A visitor opens a console page. Without a valid access cookie the console tries the refresh cookie. If that works it sets new cookies and continues; otherwise it sends the visitor to the sign-in page with `?next=` set. Requests that arrive together with the same expired token share one refresh, so token rotation does not reject all but the first.
2. The sign-in page offers a password and every other method the registered modules provide:
   - **Password:** the same check as `POST /login`: lockout, eligibility, `before.login` hooks and completion interceptors.
   - **Passkey:** `app.js` runs WebAuthn with the passkey module's options (`/login/passkey/begin`, `/login/passkey/finish`); the button appears only in browsers that support it.
   - **OAuth and SAML:** the buttons start the modules' own login routes with `redirect_uri` set to the console's `/login/done`. Because that is a local path, the callback sets the cookies and redirects without putting tokens in the URL.
   - **Emailed code:** the magic-link module sends a code (`/login/code`) that the visitor types in (`/login/code/verify`). The answer is the same whether or not the address has an account.
3. If the user has two-factor authentication, the second step asks for a code and completes the same continuation as `POST /2fa/verify-login`. After OAuth or SAML the second step cannot run on the console; the page says so and offers the password or a passkey. Other challenges, such as choosing an organization, are not supported.
4. On success the console sets the credential cookies and redirects to `next`, if it is a console page the visitor may open, or to their home page.
5. Searching and paging swap only the table. Every other link and form loads a whole page, so the console also works with JavaScript off.
6. Signing out revokes the credentials, as `POST /logout` does, and clears the cookies.

## Security

- **Cross-site requests are refused.** Every route is wrapped in Go's `http.CrossOriginProtection`, which rejects form submissions from another site by their `Sec-Fetch-Site` and `Origin` headers. The CSRF module skips `ui.*` routes for that reason. Credential cookies are also `SameSite=Lax` by default.
- **Content-Security-Policy** allows scripts, styles and requests from the console's own origin only, with no inline script or style. htmx is configured not to evaluate code, not to inject styles and not to keep page snapshots in browser storage.
- **Other headers:** `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store` on every page.
- **Redirects after sign-in** only go to clean paths inside the console.
- **Notices** after an action come from a fixed list. A message is never read from the URL, so a link cannot make the console show text of someone else's choosing.
- **Rate limiting:** the default rate-limit rules cover `ui.login`, `ui.login.2fa`, `ui.login.code.verify`, `ui.login.passkey.finish` and `ui.account.password` as credential checks, `ui.login.code` as a send, and `ui.login.passkey.begin` with the federation rule. The rate limiter reads the account from form bodies as well as JSON.
- **Bans** are checked wherever GoAuth checks that an account may be used, so a ban stops the console, your application and the identity provider alike.

## Events and Errors

The console emits no events of its own; the services it calls emit theirs, with the administrator as the actor. User changes made from the console (unlink, end session, reset two-factor, remove passkey, set password, sign out everywhere, unlock, ban with its reason and end, lift a ban) are recorded as `admin.user.updated` with a description; creating a user is `admin.user.created`, deleting one `admin.user.deleted`. Organization changes emit the organization module's events (`org.updated`, `org.deleted`, `org.member.added`, `org.member.removed`, `org.member.role.changed`), so the RBAC module's cleanup runs as it would for an owner's change. Team changes emit the team module's `team.*` events.

Errors are shown as pages, never as JSON: `422` with the form and a message for a rejected change, `404` for something missing or a module that is not registered, `403` for a visitor who is not a super admin, and `500` for a failed lookup, which is also logged.

## Known Limitations

- **No impersonation.** Acting as another user is not built yet; its design (opt-in, a required reason, a time limit, an audit trail and a visible banner) is still to be agreed.
- **Configuration is read-only.** Settings live in code by design, so every server runs the same configuration.
- **One shared session.** The console uses the application's cookies, so it lives on the application's origin, at a path those cookies reach. This is deliberate: a separate console session would be weaker, not stronger.
- **Refresh races across servers.** Requests that arrive together share one refresh only within one server process. With several processes behind a load balancer, two of them may still try the same refresh token at the moment it expires, and rotation rejects the later one.
- **htmx 2.0.7** is vendored and was verified byte for byte against the npm release; see `internal/modules/ui/assets/THIRD_PARTY_NOTICES.txt`.
