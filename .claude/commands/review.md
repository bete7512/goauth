Review current git changes against goauth project conventions.

## Instructions

1. Run `git diff` and `git diff --cached` to see all staged and unstaged changes.

2. Check each changed file against these rules:

### Architecture Rules
- [ ] No `internal/` types imported in `pkg/` files
- [ ] Module names use `types.XModule` constants, not raw strings
- [ ] New modules have compile-time check: `var _ config.Module = (*XModule)(nil)`
- [ ] Storage access uses typed methods (`Storage.Core()`, etc.), not string lookups

### Error Handling
- [ ] Errors wrapped with context: `fmt.Errorf("what failed: %w", err)`
- [ ] Config errors use `config.ErrConfig()` not `fmt.Errorf` directly
- [ ] Module init errors are descriptive (they surface to library users)

### Code Style
- [ ] Route names use dot notation (`"module.action"`)
- [ ] Entity IDs are UUIDs, not auto-increment
- [ ] No soft delete patterns (actual deletion only)
- [ ] Logging uses structured fields: `logger.Info("msg", "key", value)`

### Testing
- [ ] New public functions have corresponding tests
- [ ] Tests use testify/suite pattern where appropriate
- [ ] Mocks use uber/mock, not hand-written fakes

### Module Contract
- [ ] New modules implement all 8 `config.Module` methods
- [ ] Swagger spec embedded via `//go:embed`
- [ ] Custom storage parameter in `New()` with fallback to deps

3. Report findings as:
   - **ISSUE** [file:line] - description of the violation
   - **WARNING** [file:line] - suggestion for improvement (not a hard rule)
   - **OK** - if everything passes

4. For each ISSUE, suggest the specific fix.
