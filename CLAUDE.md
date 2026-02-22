# GoAuth - Claude Context

## What This Is
Modular, framework-agnostic authentication **library** for Go (not a standalone service).
Module path: `github.com/bete7512/goauth`. Go 1.25.

## Architecture

### Package Layout
- `pkg/` = public contracts (auth, config, models, types, **modules/**). Never leak `internal/` types here.
- `pkg/modules/` = thin proxy packages wrapping `internal/modules/` — the only way external consumers import bundled modules.
- `internal/` = implementation (modules, events, middleware, security, utils).
- `storage/` = storage backends (GORM built-in, cache decorators).
- `examples/` = integration examples for each web framework.

### Three-Phase Lifecycle
```
auth.New(config) → auth.Use(module) → auth.Initialize(ctx)
```
Order is enforced: `Use()` panics after `Initialize()`. This exists because modules depend on each other and need deterministic registration order.

### Critical Constraints
- **Session vs Stateless are mutually exclusive.** Registering both panics.
- **Core module is auto-registered.** Never register it manually via `Use()`.
- **If neither Session nor Stateless is registered, Stateless is the default** with refresh token rotation enabled.
- **Storage is type-safe.** Use `Storage.Core()`, `Storage.Session()`, etc. No string-based lookups.

## Public Interfaces (pkg/types)
- `types.Logger` — any logger implementation; `pkg/config` uses this, not the internal logrus type.
- `types.SecurityManager` — all security ops (hash, JWT, OTP, encrypt). Concrete: `internal/security.SecurityManager`.
- `types.OpenAPIServer`, `types.OpenAPISecurityScheme` — OpenAPI config types (not Swagger-prefixed).

## Module Contract

Every module implements `config.Module` (8 methods): `Name()`, `Init()`, `Routes()`, `Middlewares()`, `Models()`, `RegisterHooks()`, `Dependencies()`, `OpenAPISpecs()`.

Required patterns:
- Compile-time check: `var _ config.Module = (*XModule)(nil)`
- Dependencies via `ModuleDependencies` struct passed to `Init(ctx, deps)`
- Module names use `types.XModule` constants, never raw strings
- Directory structure: `internal/modules/<name>/module.go`, `handlers/`, `services/`, `docs/openapi.yml`
- OpenAPI specs embedded: `//go:embed docs/openapi.yml` → `var openapiSpec []byte`
- Custom storage accepted in `New()`, falls back to `deps.Storage.X()` if nil

Reference implementation: `internal/modules/core/module.go`

### OpenAPI Docs Rule

**Whenever you add, modify, or remove a DTO or HTTP endpoint in any module, you MUST update that module's `docs/openapi.yml`.** This includes:
- New routes → add path + request/response schemas
- Modified DTOs → update the corresponding schema definitions
- Removed endpoints → remove from spec; Changed shapes → update schemas

Every module's spec lives at `internal/modules/<name>/docs/openapi.yml` and is embedded via `//go:embed docs/openapi.yml`.

### Service Pattern

Exported interface / unexported struct:
```go
type AdminService interface { ... }    // exported — handlers/tests depend on this
type adminService struct { ... }       // unexported — real implementation
func NewAdminService(...) *adminService { ... }  // constructor satisfies interface
```
- **Handlers depend on the interface**, never the concrete struct
- **Service methods return `*types.GoAuthError`**, not `error`
- **Testing**: Use `s.Nil(authErr)` / `s.NotNil(authErr)`, never `s.NoError()` / `s.Error()`
- **Mock generation**: `//go:generate mockgen` directive at top of service file

Reference implementation: `internal/modules/admin/services/users.go`

## HTTP Utilities

- `http_utils.RespondSuccess(w, data, msg)` — 200 OK
- `http_utils.RespondCreated(w, data, msg)` — 201 Created (use for resource creation, e.g. signup)
- `http_utils.RespondList(w, items, total, sortField, sortDir)` — paginated list
- `http_utils.RespondError(w, statusCode, string(types.ErrXxx), msg)` — always use `types.Err*` constants, never raw strings

## Storage

```
types.Storage
  ├── Core() → CoreStorage (Users, Tokens, VerificationTokens)
  ├── Session() → SessionStorage (Sessions)
  └── Stateless() → StatelessStorage (Blacklist)
```
GORM: `storage/gorm/`. Cache decorator: `storage/cache/memory/`

## Error Handling

- Config errors: `config.ErrConfig("message")`, check with `config.IsConfigErr(err)`
- Module init errors must be descriptive — they surface directly to the library user

## Events

- EventBus with typed `types.EventType` events
- Default backend: worker pool (10 workers, 1000 queue size). Custom: implement `types.AsyncBackend`
- `EmitSync` blocks and returns error — used for intercept points (e.g. 2FA challenge in session login)
- When adding `EmitSync` calls, update tests to set mock expectations for the event bus
- Subscribe: `auth.On(event, handler)` or module's `RegisterHooks(events)`

## Code Style

- Route names: dot notation (`"core.login"`, `"admin.users.list"`, `"audit.cleanup"`)
- Middleware priority: higher = runs first (CORS=100, RequestID=90, Auth=50)
- All entity IDs are UUIDs (`google/uuid`). No soft deletes.
- Logging: use `deps.Logger` (type `types.Logger`), **never `fmt.Printf`**
- Background goroutines in `Init()`: use `ctx.Done()` for shutdown, `context.Background()` for the work itself

## Listing Endpoints

Pattern: `ParseListingOpts(r)` → per-entity opts → `Normalize(maxLimit)` → service → `RespondList`
Response: `types.APIResponse[types.ListResponse[T]]` with `list`, `sort_field`, `sort_dir`, `total`.
Per-entity opts embed `ListingOpts` from `pkg/models/listing.go`. Never add entity fields to base opts.
OpenAPI spec: add `offset`, `limit`, `sort_field`, `sort_dir` params + `ListResponse` schema.

Allowed sort fields — Users: `created_at`, `email`, `username`, `name` · Sessions: `created_at`, `expires_at`, `ip_address` · Audit: `created_at`, `action`, `severity`, `actor_id`

## Testing

- Framework: testify/suite + uber/mock (mockgen)
- Generate mocks: `make mocks` · Unit tests: `make test` · Specific: `make test-core`, `make test-session`
- Integration: `make test-integration` (needs `GOAUTH_TEST_DSN`)

## Build

- `make build` · `make lint` · `make clean`
- Always run `make build` to catch compilation errors before committing.

## Before You Build Anything
**When asked to implement or change something, STOP and think through these before writing code.**
Surface what the change enables, what it costs, and what adjacent concerns it raises. Then discuss, then build.

## Current State

Branch: `dev`. Recent completed work:
- **Public API surface**: `pkg/types/logger.go` + `pkg/types/security_manager.go` promoted to public interfaces; `pkg/config` no longer imports `internal/` types
- **Proxy packages**: `pkg/modules/` created for all bundled modules — external consumers must use these, not `internal/modules/`
- **OpenAPI naming**: all `docs/swagger.yml` → `docs/openapi.yml`; vars `swaggerSpec` → `openapiSpec`; types `SwaggerServer` → `OpenAPIServer`, `SwaggerSecurityScheme` → `OpenAPISecurityScheme`; method `GenerateSwaggerDocs` → `GenerateOpenAPIDocs`
- **Audit module**: `POST /admin/audit/cleanup` endpoint added; 24h background cleanup goroutine wired in `Init()`
- **Signup**: now returns 201 Created via `http_utils.RespondCreated`
