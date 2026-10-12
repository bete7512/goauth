---
name: review
description: Review current git changes against goauth project conventions.
---

Review current git changes against goauth project conventions.

## Instructions

1. Run `git diff` and `git diff --cached` to see all staged and unstaged changes.

2. Check each changed file against these rules:

### Architecture Rules
- [ ] No `internal/` types imported in `pkg/` files
- [ ] Module names use `types.XModule` constants, not raw strings
- [ ] New modules have compile-time check: `var _ config.Module = (*XModule)(nil)`
- [ ] Storage access uses typed methods (`Storage.Core()`, etc.), not string lookups
- [ ] OpenAPI specs use `docs/openapi.yml` naming (not swagger.yml)

### Error Handling
- [ ] Service methods return `*types.GoAuthError`, not `error`
- [ ] Config errors use `config.ErrConfig()` not `fmt.Errorf` directly
- [ ] HTTP responses use `http_utils.RespondError` with `types.Err*` constants

### Code Style
- [ ] Route names use dot notation (`"module.action"`)
- [ ] Entity IDs are UUIDs, not auto-increment
- [ ] No soft delete patterns (actual deletion only)
- [ ] Logging uses `deps.Logger` (type `types.Logger`), never `fmt.Printf`

### Testing
- [ ] New public functions have corresponding tests
- [ ] Tests use testify/suite + gomock pattern
- [ ] Test assertions use `s.Nil(authErr)` / `s.NotNil(authErr)` for GoAuthError
- [ ] AuthInterceptors set to `interceptor.NewRegistry()` in test deps

### Module Contract
- [ ] New modules implement all 8 `config.Module` methods
- [ ] OpenAPI spec embedded via `//go:embed docs/openapi.yml`
- [ ] Custom storage parameter in `New()` with fallback to deps

3. Report findings as:
   - **ISSUE** [file:line] - description of the violation
   - **WARNING** [file:line] - suggestion for improvement (not a hard rule)
   - **OK** - if everything passes

4. For each ISSUE, suggest the specific fix.
