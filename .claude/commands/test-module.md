Run tests for a specific goauth module.

## Arguments
$ARGUMENTS - Required: module name (e.g., "core", "session", "csrf", "captcha", "oauth", "twofactor", "ratelimiter", "magiclink", "admin", "notification", "stateless", "events")

## Instructions

1. Map the module name to its test path:
   - "core" → `go test ./internal/modules/core/... -v -count=1`
   - "session" → `go test ./internal/modules/session/... -v -count=1`
   - "stateless" → `go test ./internal/modules/stateless/... -v -count=1`
   - "events" → `go test ./internal/events/... -v -count=1`
   - "csrf" → `go test ./internal/modules/csrf/... -v -count=1`
   - "captcha" → `go test ./internal/modules/captcha/... -v -count=1`
   - "oauth" → `go test ./internal/modules/oauth/... -v -count=1`
   - "twofactor" → `go test ./internal/modules/twofactor/... -v -count=1`
   - "ratelimiter" → `go test ./internal/modules/ratelimiter/... -v -count=1`
   - "magiclink" → `go test ./internal/modules/magiclink/... -v -count=1`
   - "admin" → `go test ./internal/modules/admin/... -v -count=1`
   - "notification" → `go test ./internal/modules/notification/... -v -count=1`
   - "storage" → `go test ./storage/... -v -count=1`
   - "security" → `go test ./internal/security/... -v -count=1`

2. If no test files exist for the module, report that and list which source files lack test coverage.

3. For failures: read the test file, identify the failing assertion, and suggest fixes with file:line references.

4. Report: total tests, passed, failed, and any tests that were skipped.
