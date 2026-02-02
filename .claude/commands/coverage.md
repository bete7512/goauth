Analyze test coverage for the goauth project.

## Instructions

1. Run `make test-coverage` to generate coverage.out.

2. Parse the coverage output and organize by package:
   - `internal/modules/core/...`
   - `internal/modules/session/...`
   - `internal/modules/stateless/...`
   - `internal/modules/csrf/...`
   - `internal/modules/captcha/...`
   - `internal/modules/oauth/...`
   - `internal/modules/twofactor/...`
   - `internal/modules/ratelimiter/...`
   - `internal/modules/magiclink/...`
   - `internal/modules/admin/...`
   - `internal/modules/notification/...`
   - `internal/events/...`
   - `internal/security/...`
   - `storage/...`
   - `pkg/...`

3. For each package, report:
   - Overall coverage percentage
   - Functions with 0% coverage (these need tests most)
   - Functions below 50% coverage

4. Produce a priority list: which untested functions are most important to cover, ranked by:
   - Public API functions (in `pkg/`) first
   - Core module functions second
   - Functions handling errors or edge cases third

5. For the top 5 uncovered functions, suggest what the test should verify (happy path, error cases, edge cases).
