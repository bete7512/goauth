---
name: add-module
description: Scaffold a new goauth module following established patterns.
---

Scaffold a new goauth module following established patterns.

## Arguments
$ARGUMENTS - Required: module name in lowercase (e.g., "passwordless", "apikey", "webhook")

## Instructions

Use `internal/modules/core/module.go` as the reference implementation.

### 1. Directory Structure
```
internal/modules/<name>/
  module.go
  handlers/handlers.go
  services/service.go       # exported interface / unexported struct
  docs/openapi.yml
  migrations/{postgres,mysql,sqlite}/  # if DB tables needed
```

### 2. module.go Must Include
- `//go:embed docs/openapi.yml` + `var openapiSpec []byte`
- Compile-time check: `var _ config.Module = (*<Name>Module)(nil)`
- All 8 `config.Module` methods: Name, Init, Routes, Middlewares, RegisterHooks, Dependencies, OpenAPISpecs, Migrations

### 3. Service Pattern
- Exported interface, unexported struct: `type <Name>Service interface {}` / `type <name>Service struct {}`
- Methods return `*types.GoAuthError`, not `error`
- Add `//go:generate mockgen` directive

### 4. Also Create
- `types.<Name>Module` constant in `pkg/types/module.go`
- `pkg/modules/<name>/<name>.go` proxy package
- Config struct in `pkg/config/config.go` if needed
- Test file verifying module satisfies `config.Module`

### 5. Do NOT
- Auto-register the module
- Use `swagger.yml` naming (use `openapi.yml`)
- Use `Models()` or `SwaggerSpec()` (outdated — use `Migrations()` and `OpenAPISpecs()`)
