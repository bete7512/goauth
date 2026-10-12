---
name: test
description: Run tests for the goauth project.
---

Run tests for the goauth project.

## Arguments
$ARGUMENTS - Optional: "verbose", "integration", "coverage", "bench", or empty for default unit tests.

## Instructions

Based on the argument:
- No argument or "unit": Run `make test`
- "verbose": Run `make test-verbose`
- "integration": Run `go test -tags=integration ./tests/integration/... -v -count=1`
- "coverage": Run `make test-coverage-html` then summarize results
- "bench": Run `make test-bench`

After running:
1. If tests pass, report pass count and any skipped tests
2. If tests fail, analyze each failure:
   - Read the failing test file
   - Identify root cause (assertion mismatch, nil pointer, missing mock, etc.)
   - Suggest fix with file:line reference
3. If compilation errors, fix them and re-run
