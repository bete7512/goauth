Run tests for the goauth project.

## Arguments
$ARGUMENTS - Optional: "verbose", "integration", "coverage", or empty for default unit tests.

## Instructions

Based on the argument provided:
- No argument or "unit": Run `make test`
- "verbose": Run `make test-verbose`
- "integration": Run `make test-integration` (requires GOAUTH_TEST_DSN env var)
- "coverage": Run `make test-coverage-html` then read coverage.out to summarize results

After running:
1. If tests pass, report the pass count and any skipped tests
2. If tests fail, analyze each failure:
   - Read the failing test file to understand what it tests
   - Identify the root cause (assertion mismatch, nil pointer, missing mock, etc.)
   - Suggest a specific fix with file and line reference
3. If compilation errors, fix them and re-run
