# Changelog

All notable changes to GoAuth are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor release may contain breaking changes; they are listed first.

## [Unreleased]

### Added
- **Docs search visibility**: every docs page and post has a hand-written search title (`seoTitle`), description and `keywords`; docs pages carry breadcrumb and `dateModified` structured data and the sitemap carries `lastmod` from git; the docs sync fails when a page has no description. New pages: a comparison with Goth, Authboss, Ory Kratos, Keycloak and hosted services (`/docs/comparison`), and how-to posts on passkeys, JWT refresh token rotation and building an OpenID Connect provider in Go. `pkg/auth` gains a package doc comment for pkg.go.dev. The older blog posts are dated when they were published (2025-08-22); their URLs are unchanged.
- **RBAC example** (`examples/rbac`): "Acme Tracker", a multi-package service showing every rbac guard (global, organization and team scopes, ownership lookups, OnlyIf/AllowIf, TeamsWhere, checks in code), with seed data, a walkthrough script and a scenario test.

- **RBAC module** (`pkg/modules/rbac`, experimental): role-based access control for the application's own routes and services. Permissions have the form `resource:action` and are declared by being used; roles hold grants that may use wildcards (`invoice:*`, `*:read`, `billing.*:read`, `*`). `Require` and `Resource` guard routes, `Can`, `Check` and `For` decide in code, and `AllowIf`, `OnlyIf`, `Decide` and `OnDeny` attach the application's own rules. Roles are defined in code or created at runtime through new endpoints under `/rbac/...`, and with `Organizations: true` per organization under `/org/{orgId}/...`, where a member's `owner`, `admin` or `member` role becomes a built-in role. Nobody can create, change, give or take away a role that grants more than they hold. Checks read current state on every request; permissions are never written into tokens. GoAuth's own permissions live in the reserved `goauth.` namespace, which a bare `*` does not match. New tables `rbac_roles` and `rbac_role_assignments`; `types.Storage` gains `RBAC()`, which custom storage implementations must add (return nil when unused), and `types.StorageSet` gains `RBACStore`. Organization roles depend on the Organization module. Not implemented: deny rules, and roles for tokens issued to other applications.
- **UI module** (`pkg/modules/ui`): a server-rendered console built with `html/template` and embedded htmx 2.0.7, with no build step and nothing loaded from other origins. Super admins get an overview, user search and editing, user deletion, application-wide roles (with the RBAC module) and the audit log (with the audit module). With `UserPages`, every user gets a sign-in page and an account page. It signs in with the application's cookies, refreshes them when the access token expires, supports the two-factor step, and refuses to start in bearer-only mode. Every route is protected by `http.CrossOriginProtection` and a strict Content-Security-Policy, and the CSRF module skips `ui.*` routes. A coverage test fails when a module adds an administrative route with neither a console page nor a written exemption. Every area GoAuth manages has pages: users (create, edit, delete, unlock, set a password, sign out everywhere, send reset and verification emails; linked accounts, sessions, two-factor reset, passkeys, connected applications; roles and memberships; activity), organizations (create for an owner, edit, suspend, delete, members, ownership transfer, invitations, organization roles), platform invitations, roles and permissions (edit grants, who holds each role, permission catalog), OIDC clients (create, edit, rotate the secret, delete) and a read-only settings page. Areas whose module is not registered stay in the sidebar, greyed out with the module to register. Depends only on Core. `Config.Path` mounts the console at a path of its own, such as `/admin`, outside `BasePath`; `Initialize` fails if the credential cookies' path would not reach it.
- **Team module** (`pkg/modules/team`, experimental): nested teams inside organizations, up to five levels, under `/org/{orgId}/teams/...` (list or tree, create, get, update, move with everything beneath, delete, members as `lead` or `member`). Organization owners and admins manage every team; leads manage their team and every team beneath it; moving or deleting a team needs the right to manage where it sits; members may leave. Team memberships are tied to the organization membership they were made for. Events `team.created`, `team.updated`, `team.moved`, `team.deleted`, `team.member.added`, `team.member.removed`, `team.member.role.changed`; error codes `TEAM_*`. New tables `teams` and `team_members`. Depends on the Organization module.
- **Roles inside teams** in the RBAC module (`Config.Teams`, which needs `Organizations` and the team module): a role held on a team applies to it and every team beneath it, the organization's and application-wide roles apply in its teams, team leads hold the built-in `lead` role (`*` on the application's own permissions) and members `member`, and the organization's roles can be assigned in its teams. New options `rbac.InTeam`, `rbac.TeamParam`, `rbac.TeamFrom`, `rbac.ScopeTeam`, `Module.TeamsWhere` and `Subject.TeamsWhere` (which teams of an organization the user may act in, for list routes), and routes `/org/{orgId}/teams/{teamId}/roles`, `/members/{userId}/roles` and `/role-assignments`. `models.RoleScopeTeam`.
- Console additions: an editable account page for every user it admits (profile, password change, sessions, passkeys, connected applications); bulk user actions (deactivate, activate, sign out, delete); CSV exports of users, organizations and the audit log, guarded against spreadsheet formulas; bans with a reason and an end (`1h` to `30d`, or until lifted); sending organization invitations as a super admin (`AdminService.InviteMember`) and importing platform and organization invitations from CSV (up to 200 rows); team pages; overview charts of sign-ups, sign-ins and failed sign-ins over 30 days; sign-in with passkeys, OAuth, SAML and emailed codes (magic link) besides the password. Concurrent requests with the same expired token share one refresh. The vendored htmx file was verified against the npm release.
- **User bans**: `User.BannedAt`, `BannedUntil` and `BanReason` (core migration `005_add_ban_columns`), `User.Banned(now)`, and `AdminService.Ban`/`Unban`, which revoke the user's credentials. A ban with an end lifts itself.
- Optional per-day counting interfaces `models.UserSignupCounter` and `models.AuditActionCounter` (with `models.DailyCount`), implemented by the GORM stores, for the console's charts.
- Default rate-limit rules for the console's new routes: `ui.account.password`, `ui.login.code.verify` and `ui.login.passkey.finish` as credential checks, `ui.login.code` as a send, `ui.login.passkey.begin` with the federation rule.
- `config.RouteInfo.Absolute`: a module route mounted at its path as given instead of under `BasePath`. The authorization server branch uses the same field for RFC 8414 metadata.
- Administrator operations for the console, each requiring a super admin: in the admin service, user creation, unlocking, setting a password, signing out everywhere, unlinking accounts, ending sessions, resetting two-factor and removing passkeys; an organization admin service (list, create for an owner, edit, suspend, delete, members, ownership transfer, invitations); listing and cancelling every platform invitation (`InvitationRepository.List`, which custom storage implementations must add).
- `types.ErrNotFound` (`NOT_FOUND`) for resources without a code of their own.
- `ModuleDependencies.Lookup`, so a module can find another registered module by name for optional features.
- `types.CredentialRefresher` and `types.CredentialRevoker`, implemented by the session and stateless modules, and `types.TwoFactorLoginVerifier`, implemented by the two-factor module: refresh, sign-out and the second sign-in step outside HTTP.
- The rate limiter reads the email, username or phone from form-encoded bodies as well as JSON, and the default credential rules cover `ui.login` and `ui.login.2fa`.
- `can(grants, permission)` in the TypeScript client, which matches the grants returned by `GET /me/permissions` the way the server does.
- **Identity provider module** (`pkg/modules/idp`, experimental): GoAuth as an OpenID Connect provider, so other applications can sign users in with your accounts. Authorization code flow with PKCE, confidential clients (client ID and secret) and public clients, ID tokens signed with RS256 by a key of the module's own, an opaque access token for the UserInfo endpoint, rotating refresh tokens with reuse detection, consent remembered per user and application, `prompt=login`/`prompt=consent`/`max_age`, a discovery document and key set, a claims function for custom claims, connected-application listing and revocation for users, and client administration through configuration or an admin API. Client secrets, codes and tokens are stored as digests. New tables `idp_clients` and `idp_grants`; `types.Storage` gains `IDP()`, which custom storage implementations must add (return nil when unused). The admin API depends on the Admin module. Not implemented: sign-out protocols, `prompt=none`, implicit and hybrid flows, dynamic client registration.
- **Sign-in and consent page of the identity provider.** The module now serves the page the authorization endpoint sends the browser to, at `{Issuer}/consent`, so a host no longer has to build one: a sign-in form (password with email or username, the two-factor step, and the OAuth and SAML connections that are registered) followed by an approval screen, or straight back to the client when there is nothing to ask. It is plain HTML with one stylesheet and no script, reads the signed-in user from the application's credential cookies, and signs in through the same code as the login route. Forms are protected by `http.CrossOriginProtection` and a Content Security Policy that forbids framing; the CSRF module skips them. A request that cannot be returned to the client is shown on the page instead of as JSON. New option `IDPModuleConfig.AppName`; new routes `idp.page`, `idp.page.signin`, `idp.page.2fa`, `idp.page.decision` and `idp.page.asset`, the two sign-in routes covered by the default credential rate limits. Setting `ConsentURL` keeps the page in the host's frontend, as before. Not on the page: passkeys, emailed codes, sign-up, password reset and client logos.
- Default rate-limit rules for the identity provider: `idp_authorize_ip` (60 per minute) and `idp_token_ip` (300 per minute).
- Audit actions `auth.idp.signin`, `auth.idp.consent.denied`, `auth.idp.grant.revoked`, `admin.idp.client.*` and `security.idp.token.reuse`.
- `internal/oauthproto` (redirect URI, PKCE and scope rules) and `security.TokenSigner` (asymmetric signing of tokens that are not first-party credentials), shared with the authorization server work.
- **SAML module** (`pkg/modules/saml`): SAML 2.0 service provider with SP-initiated login over the HTTP-Redirect binding, an HTTP-POST Assertion Consumer Service, optional IdP-initiated login, SP metadata, signed AuthnRequests, encrypted assertions and attribute mapping for Keycloak, Okta, Entra ID and Shibboleth naming schemes. Linked subjects live in the `accounts` table, so the module depends on the OAuth module. Signature verification is delegated to `github.com/crewjam/saml`.

### Changed

- **Identity provider: an empty `ConsentURL` now means the module's own page.** It used to default to `FrontendConfig.URL + "/oidc/consent"`; a host that relies on that default must set `ConsentURL` to that address. The old default remains only with `Security.AuthMode: "bearer"`, where the module's page cannot work. `Initialize` fails when `Security.Session.Path` keeps the credential cookies from the page.
- Identity provider: a sign-in made after an authorization request satisfies its `max_age`, as it already satisfied `prompt=login`. Before, `max_age=0` was only met when the user approved within the same second as signing in.
- `types.Storage` gains `Team()`, which custom storage implementations must add (return nil when unused), and `types.StorageSet` gains `TeamStore`.
- Banned users get `USER_BLOCKED` (403) wherever eligibility is checked: sign-in, refresh, every authenticated request and the identity provider.
- The OAuth callback and the SAML ACS accept a `redirect_uri` that is a local path (such as `/admin/login/done`): they set the credential cookies and redirect without tokens in the URL, or add `error=challenge_required` / `error=cookies_disabled`. Absolute URLs behave as before.
- The console's account routes are always registered: super admins always have an account page, other users only with `UserPages`.

### Fixed
- **Console**: a browser already signed in to the application as a non-administrator was shown "This console is for administrators" with no way to switch accounts. It is now sent to the console's sign-in page, which says who is signed in.

- **Passkeys could not be saved.** The model's `AAGUID` field mapped to a column `aa_guid`, but the migrations create `aaguid`, so registering a passkey failed on every database.
- Listing organization members without a `sort_field` (`GET /org/{orgId}/members`) failed, because the default sort column `created_at` does not exist on memberships; the default is now `joined_at`.
- Deleting an organization left its memberships and invitations behind. They are now deleted in the same transaction.

- Searching users (`GET /admin/users?query=`) and organizations failed on SQLite and MySQL, which have no `ILIKE`. Search now uses `LOWER(...) LIKE ... ESCAPE` on every dialect and treats `%` and `_` in the query as literal characters.
- The Fiber adapter dropped the status and headers of responses without a body, such as redirects and responses that only set cookies, and joined repeated headers such as `Set-Cookie` into one.
- The CSRF module no longer rejects the SAML Assertion Consumer Service. The identity provider posts to it across sites and cannot hold a CSRF token; the endpoint is protected by the signed response and its request binding instead.

## [0.3.0-beta.1] - 2026-10-26

The first public beta and the start of a new release line. Every earlier version is retracted (see below). Moving from v0.2.x is a maintenance deployment and every user signs in again; follow [Upgrading from v0.2.x](docs/docs/upgrade.md#upgrading-from-v02x).

### Breaking changes

- **Go 1.26 or later is required.** The advisory fixes in `golang.org/x/text` depend on a release that needs Go 1.26 (#38).
- **Bundled modules are imported from `pkg/modules/<name>`.** The `internal/modules/...` paths shown in the v0.2.x README cannot be imported from another Go module. Module constructors take one config argument, and custom storage moves into it, for example `session.New(&config.SessionModuleConfig{CustomStorage: store})`.
- **Session and stateless authentication are separate modules** and mutually exclusive. Stateless is registered when neither is.
- **Credentials issued by v0.2.x are rejected.** Tokens now carry and require issuer, audience, purpose and subject claims, and access validation checks the current user and session state online.
- **Two-factor login requires `temp_token` plus `code`.** Verifying with only a user ID is no longer accepted.
- **Rate limiting is on by default** (#32). Tests and load tools that send many requests from one address need `RateLimit: &config.RateLimitModuleConfig{Disabled: true}` or their own rules.
- **Cookies are Secure by default** (#37). Plain-HTTP development needs `Security.Session.AllowInsecureCookies: true`; assigning `Security.Session.Secure` has no effect.
- **A locked account answers `INVALID_CREDENTIALS` (401)**, like a wrong password, instead of `ACCOUNT_LOCKED` (423). Set `Security.Lockout.RevealLocked` for the old answer (#39).
- **OAuth sign-up requires a provider-verified email** (#40). Microsoft tenants need the optional `xms_edov` ID-token claim; `OAuthModuleConfig.AllowUnverifiedEmailSignup` restores the old behavior.
- **Single-use tokens and codes are stored as digests** (#42). GoAuth cannot show a token again after sending it, and invitation links require `CallbackURL` (or `InvitationCallbackURL` for organizations).
- **Password length is measured in bytes, 8 to 72**, matching bcrypt's input limit.
- **The v0.2.x `ratelimiter` module is gone**, replaced by `ratelimit` with a new configuration.

### Security

- Every sign-in method (password, OAuth, magic link, passkeys, invitations, MFA completion, organization switch) completes through one engine that enforces MFA and account eligibility. Pending-MFA and refresh tokens can no longer authenticate requests.
- Access validation is online: password changes and resets, suspension, session deletion and organization removal take effect on the next request.
- Single-use consumption, refresh rotation and TOTP acceptance are atomic; concurrent replays have exactly one winner.
- OIDC ID tokens are verified for signature, issuer, audience and nonce. OAuth state is bound to the browser, and PKCE is always used.
- Organization admins cannot grant themselves ownership, and invitations cannot grant owner.
- Missing route protection, route collisions and invalid signing keys fail startup instead of serving unprotected routes or falling back to HS256.
- Password reset requires a reset-purpose token and enforces the password policy.
- Built-in routes are rate limited per client IP and per submitted identifier (#32).
- Phone reset and verification codes are bound to their account and invalidated after five wrong guesses (#35).
- Each TOTP code is accepted once, even inside the ±30-second window (#36).
- Lockout no longer reveals whether an account exists, and unknown accounts cost one password hash so timing does not reveal them either (#39).
- Dependencies with known advisories are upgraded: `jackc/pgx` (GO-2026-5004) and `golang.org/x/text` (#38).

### Added

- Modules: `session`, `stateless`, `organization`, `invitation`, `passkeys` (WebAuthn), `audit` and `ratelimit`.
- RS256 and ES256 signing with a JWKS endpoint, signing-key rotation with retained verification keys, and versioned encryption with key rotation.
- Per-module SQL migrations with checksums, a coordinated runner, MySQL dirty-state handling, `MigrationStatus`, `RollbackModule` and `GenerateMigrationFiles`.
- `Auth.SignIn` and `Auth.Authenticate` for direct Go use; `RequireAuth` fails closed before initialization and after shutdown.
- `config.Component`, a two-method module contract; existing `config.Module` implementations still work.
- Optional transactional outbox for authentication events (`DurableEvents`).
- `Config.TrustedProxies`, `Config.RateLimit`, `MaxConcurrentRequests`, `MaxRequestBodyBytes`, `Admission` and `Observer`.
- Chi, Gin and Fiber adapters as separate Go modules, and a TypeScript client generated from the OpenAPI specs.
- CI lint job: golangci-lint, govulncheck, `go mod tidy` and mock drift checks, plus `make check` (#44).

### Fixed

- MySQL could not create the migrations tracking table (error 1170) (#33).
- `GET /me` returned a partial profile with `active` and `email_verified` always false (#34).
- The second phone code in a database failed with a 500 because phone-only rows shared an empty token value (#35).
- ES256 JWKS coordinates dropped a leading zero byte for about one key in 128; key IDs are unchanged (#44).
- `NewConfigurationError` ignored its message (#44).

## Retracted versions

`v0.1.0-alpha.1`, `v0.1.0`, `v0.1.1`, `v0.2.0` and `v0.2.1` were published before this changelog and have the security issues fixed in 0.3.0-beta.1. They are retracted in `go.mod`, so the Go tooling warns anyone who depends on them. Their tags and release notes have been removed from GitHub; the Go module proxy keeps the code, so those version numbers can never be reused.

[Unreleased]: https://github.com/bete7512/goauth/compare/v0.3.0-beta.1...HEAD
[0.3.0-beta.1]: https://github.com/bete7512/goauth/releases/tag/v0.3.0-beta.1
