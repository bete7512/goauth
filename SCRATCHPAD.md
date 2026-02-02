# GoAuth Scratchpad

Cross-session memory for Claude Code. Update this file as work progresses.

## Current Focus

Branch: `feat/storage-architecture-update`
Active work: Storage architecture refactor, CSRF and captcha module updates.

## In Progress

<!-- Update this section when starting/pausing work -->

- Storage architecture: migrated to type-safe `Storage.Core()` / `Storage.Session()` / `Storage.Stateless()` pattern
- CSRF module: updated, has tests
- Captcha module: updated, has tests

## Module Status

| Module | Tests | Swagger | Handlers | Services | Notes |
|--------|-------|---------|----------|----------|-------|
| core | 3 files | yes | yes | yes | Reference implementation |
| session | 2 files | yes | yes | yes | |
| stateless | none | none | yes | yes | Needs tests + swagger |
| csrf | 2 files | yes | no (inline) | yes | Recently updated |
| captcha | 2 files | yes | no (inline) | yes | Recently updated |
| notification | none | yes | yes | yes | Needs tests |
| twofactor | none | yes | yes | yes | Needs tests |
| oauth | none | none | yes | yes | Needs tests + swagger |
| ratelimiter | none | none | no | yes | Needs tests + swagger + handlers |
| magiclink | none | none | yes | yes | Needs tests + swagger |
| admin | none | none | yes | yes | Needs tests + swagger |

## Decisions Log

<!-- Append-only. Format: [date] Decision - Reason -->

- [2025] Type-safe storage over string-based - string lookups caused silent bugs where wrong repository type was returned
- [2025] Session/Stateless mutual exclusion via panic - fail fast on misconfiguration rather than subtle runtime errors
- [2025] Core auto-registered - every app needs auth basics, forcing manual registration adds friction for no benefit
- [2025] Module pattern with 8-method interface - standardizes lifecycle, makes modules pluggable without touching core code
- [2025] Event system with DLQ + retry - authentication events (login, signup) must be reliable for audit trails

## Known Issues / Tech Debt

- Integration tests are placeholder only (`tests/integration/`)
- 7 of 11 modules have no tests
- 5 modules missing swagger specs
- `ratelimiter` module has no handlers directory (logic may be inline in services)
- `StorageConfig` struct in `pkg/config/storage.go` is deprecated but still exists
- `CaptchaModuleConfig.Provider` is a raw string - should be a typed enum (`types.CaptchaProvider`) so invalid providers fail at compile time instead of silently falling through to "none"
- `CaptchaModuleConfig.ApplyToRoutes` is `[]string` - should use typed route names (e.g. `types.RouteName`) so misspelled routes are caught at compile time instead of silently not matching
- Same `[]string` route name problem exists in `MiddlewareConfig.ApplyTo`, `ExcludeFrom`, and `CSRFModuleConfig.ExcludePaths`
- `middleware.Manager` had no tests - the `ApplyTo` bug went undetected because of this
- Captcha providers were sending form params as URL query string instead of POST body - unit tests passed because test servers read query params, but real APIs rejected it
