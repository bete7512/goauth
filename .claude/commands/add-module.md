Scaffold a new goauth module following established patterns.

## Arguments
$ARGUMENTS - Required: module name in lowercase (e.g., "passwordless", "apikey", "webhook")

## Instructions

Use `internal/modules/core/module.go` as the reference implementation. Create a new module with this structure:

### 1. Directory Structure
```
internal/modules/<name>/
  module.go          # Module implementation
  handlers/
    handler.go       # HTTP handlers
    routes.go        # Route definitions
  services/
    service.go       # Business logic
  docs/
    swagger.yml      # OpenAPI spec (minimal placeholder)
```

### 2. module.go Must Include
- Package declaration matching module name
- Struct: `<Name>Module` with `deps`, `handlers`, `config`, and optional `customStorage` fields
- `//go:embed docs/swagger.yml` for swagger spec
- Compile-time check: `var _ config.Module = (*<Name>Module)(nil)`
- `New(cfg, customStorage)` constructor accepting optional custom storage
- All 8 methods of `config.Module` interface:
  - `Name()` returns `string(types.<Name>Module)` - you'll need to add this constant
  - `Init(ctx, deps)` gets storage from custom or `deps.Storage`
  - `Routes()` returns handler routes
  - `Middlewares()` returns middleware configs
  - `Models()` returns database models for migration
  - `RegisterHooks(events)` registers event handlers
  - `Dependencies()` returns required module names
  - `SwaggerSpec()` returns embedded swagger bytes

### 3. Also Do
- Add `<Name>Module` constant to `pkg/types/modules.go` (or where module constants live)
- Add module config struct to `pkg/config/config.go` if the module needs configuration
- Add storage interface to `pkg/types/storage.go` if the module needs its own storage
- Create a basic test file `module_test.go` that verifies the module satisfies `config.Module`

### 4. Do NOT
- Auto-register the module (only core is auto-registered)
- Add it to any existing initialization code
- Create overly complex placeholder logic - keep handlers minimal until requirements are clear
