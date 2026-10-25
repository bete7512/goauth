# Changelog

All notable changes to GoAuth are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor release may contain breaking changes; they are listed first.

## [Unreleased]

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
