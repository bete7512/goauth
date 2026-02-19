# GoAuth - Claude Context

## What This Is
Modular, framework-agnostic authentication **library** for Go (not a standalone service).
Module path: `github.com/bete7512/goauth`. Go 1.25.

## Architecture

### Package Layout
- `pkg/` = public contracts (auth, config, models, types). Never leak `internal/` types here.
- `internal/` = implementation (modules, events, middleware, security, utils).
- `storage/` = storage backends (GORM built-in, cache decorators).
- `examples/` = integration examples for each web framework.

### Three-Phase Lifecycle
```
auth.New(config) → auth.Use(module) → auth.Initialize(ctx)
```
Order is enforced: `Use()` panics after `Initialize()`. This exists because modules depend on each other and need deterministic registration order.

### Critical Constraints
- **Session vs Stateless are mutually exclusive.** Registering both panics (not an error - a panic). This is intentional to fail fast on misconfiguration.
- **Core module is auto-registered.** Never register it manually via `Use()`.
- **If neither Session nor Stateless is registered, Stateless is the default** with refresh token rotation enabled.
- **Storage is type-safe.** Use `Storage.Core()`, `Storage.Session()`, `Storage.Stateless()`. No string-based repository lookups - we moved away from strings because they caused silent bugs in v1.

## Module Contract

Every module implements `config.Module` (8 methods): `Name()`, `Init()`, `Routes()`, `Middlewares()`, `Models()`, `RegisterHooks()`, `Dependencies()`, `SwaggerSpec()`.

Required patterns:
- Compile-time check: `var _ config.Module = (*XModule)(nil)`
- Dependencies via `ModuleDependencies` struct passed to `Init(ctx, deps)`
- Module names use `types.XModule` constants, never raw strings
- Directory structure: `internal/modules/<name>/module.go`, `handlers/`, `services/`, `docs/swagger.yml`
- Swagger specs embedded: `//go:embed docs/swagger.yml`
- Custom storage accepted in `New()`, falls back to `deps.Storage.X()` if nil

Reference implementation: `internal/modules/core/module.go`

### Swagger Docs Rule

**Whenever you add, modify, or remove a DTO or HTTP endpoint in any module, you MUST update that module's `docs/swagger.yml` to reflect the change.** This includes:
- New routes → add path + request/response schemas
- Modified DTOs → update the corresponding schema definitions
- Removed endpoints → remove from swagger spec
- Changed request/response shapes → update schemas accordingly

Every module's swagger spec lives at `internal/modules/<name>/docs/swagger.yml` and is embedded via `//go:embed docs/swagger.yml`.

### Service Pattern

Every module's service layer uses the **exported interface / unexported struct** pattern:

```go
// Exported interface — handlers and tests depend on this
type AdminService interface {
    ListUsers(ctx context.Context, opts models.UserListOpts) ([]*models.User, int64, *types.GoAuthError)
    GetUser(ctx context.Context, userID string) (*models.User, *types.GoAuthError)
    UpdateUser(ctx context.Context, user *models.User) *types.GoAuthError
    DeleteUser(ctx context.Context, userID string) *types.GoAuthError
}

// Unexported struct — the real implementation
type adminService struct {
    deps           config.ModuleDependencies
    userRepository models.UserRepository
}

// Constructor returns the unexported struct (satisfies the interface)
func NewAdminService(deps config.ModuleDependencies, userRepo models.UserRepository) *adminService {
    return &adminService{deps: deps, userRepository: userRepo}
}
```

Rules:
- **Interface name** = exported, clean name: `AdminService`, `CoreService`, `AuditService`
- **Struct name** = unexported (lowercase): `adminService`, `coreService`, `auditService`
- **Handlers depend on the interface**, never the concrete struct: `service services.AdminService`
- **Service methods return `*types.GoAuthError`**, not `error`. Use typed constructors (`types.NewInternalError()`, `types.NewUserNotFoundError()`, `types.NewUnauthorizedError()`, etc.). Handlers read `authErr.StatusCode`, `string(authErr.Code)`, `authErr.Message` directly — no manual mapping.
- **Mock generation** via `//go:generate mockgen` directive on the service file, targeting the interface
- **`//go:generate` line** goes at top of the service file: `//go:generate mockgen -destination=../../../mocks/mock_<name>_service.go -package=mocks <module-path>/services <ServiceInterface>`
- **Testing with `*types.GoAuthError`**: Use `s.Nil(authErr)` / `s.NotNil(authErr)`, never `s.NoError()` / `s.Error()`. Go's nil interface gotcha means a nil `*GoAuthError` passed as `error` is non-nil at the interface level.

Reference implementation: `internal/modules/admin/services/users.go`

## Storage

Interface hierarchy:
```
types.Storage
  ├── Core() → CoreStorage (Users, Tokens, VerificationTokens, ExtendedAttributes)
  ├── Session() → SessionStorage (Sessions)
  └── Stateless() → StatelessStorage (Blacklist)
```

- Each sub-storage returns typed repositories (e.g., `CoreStorage.Users()` → `models.UserRepository`)
- Transactions are scoped per storage type: `CoreStorage.WithTransaction(ctx, fn)`
- GORM implementation: `storage/gorm/`. Cache decorator: `storage/cache/memory/`
- Cache is decided at construction time, no runtime checks

## Error Handling

- Config errors: `config.ErrConfig("message")`, check with `config.IsConfigErr(err)`
- Always wrap: `fmt.Errorf("context: %w", err)`
- Module init errors must be descriptive - they surface directly to the library user
- **HTTP error codes must use `types.Err*` constants**, never raw strings:
  ```go
  // Correct
  http_utils.RespondError(w, http.StatusNotFound, string(types.ErrUserNotFound), err.Error())
  http_utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())

  // Wrong — never do this
  http_utils.RespondError(w, http.StatusNotFound, "user_not_found", err.Error())
  http_utils.RespondError(w, http.StatusInternalServerError, "internal_error", err.Error())
  ```

## Events

- EventBus with typed `types.EventType` events
- Default backend: worker pool (10 workers, 1000 queue size)
- Custom backends: implement `types.AsyncBackend` (for Redis, RabbitMQ, Kafka)
- Dead-letter queue + retry with exponential backoff for failed events
- Subscribe: `auth.On(event, handler)` or module's `RegisterHooks(events)`

## Code Style

- Route names: dot notation (`"core.login"`, `"admin.users.list"`, `"csrf.token"`)
- Middleware priority: higher = runs first (CORS=100, RequestID=90, Auth=50)
- All entity IDs are UUIDs (`google/uuid`)
- No soft deletes. Actual deletion.
- Logging: logrus with structured fields: `logger.Info("msg", "key", value)`
- Supported frameworks: net/http, Gin, Chi, Fiber (adapters in `internal/middleware/adapter.go`)

## Listing Endpoints

All listing/pagination endpoints follow the same pattern. When adding a new listing endpoint, follow these rules exactly:

### Response Format
Every listing endpoint returns `types.APIResponse[types.ListResponse[T]]`:
```json
{
  "data": {
    "list": [],
    "sort_field": "created_at",
    "sort_dir": "desc",
    "total": 0
  },
  "message": ""
}
```
Use `http_utils.RespondList(w, items, total, opts.SortField, opts.SortDir)` — never hand-build listing responses.

### Query Parameters
Every listing endpoint accepts these 4 query params: `offset`, `limit`, `sort_field`, `sort_dir`.

### Per-Entity Opts (Composition Pattern)
Each entity has its own opts struct embedding `ListingOpts` in `pkg/models/listing.go`:
```
ListingOpts (base)            ← offset, limit, sort_field, sort_dir
    ├── UserListOpts           ← + Query
    ├── SessionListOpts        ← (future: IPAddress, etc.)
    └── AuditLogListOpts       ← (future: DateRange, etc.)
```
- **Never add entity-specific fields to the base `ListingOpts`.** Create/extend the entity opts struct instead.
- Sort field allowlists are unexported maps in `listing.go` — add new allowed fields there.

### Handler Pattern
```go
opts := models.XxxListOpts{
    ListingOpts: http_utils.ParseListingOpts(r),
    // entity-specific fields from query params:
    Query: r.URL.Query().Get("query"),
}
opts.Normalize(100) // maxLimit
items, total, err := h.service.ListXxx(r.Context(), opts)
http_utils.RespondList(w, items, total, opts.SortField, opts.SortDir)
```

### Adding a New Listing Endpoint (Checklist)
1. Define `XxxListOpts` in `pkg/models/listing.go` (embed `ListingOpts`, add sort field allowlist, add `Normalize(maxLimit)`)
2. Repository interface: accept `XxxListOpts`, return `([]T, int64, error)`
3. GORM repo: apply entity filters, then `helpers.ApplyListingOpts(db, opts.ListingOpts)`
4. Service: accept `XxxListOpts`, pass through to repo
5. Handler: `ParseListingOpts(r)` → build entity opts → `Normalize(maxLimit)` → call service → `RespondList`
6. Swagger: add `offset`, `limit`, `sort_field`, `sort_dir` params + standard `ListResponse` schema
7. Tests: test `Normalize` in `listing_test.go`, update mock expectations for new signature

### Allowed Sort Fields (per entity)
- **Users:** `created_at`, `email`, `username`, `name`
- **Sessions:** `created_at`, `expires_at`, `ip_address`
- **Audit Logs:** `created_at`, `action`, `severity`, `actor_id`

## Testing

- Framework: testify/suite + uber/mock (mockgen)
- Generate mocks: `make mocks` (from `//go:generate` in `pkg/types/storage.go` → `internal/mocks/`)
- Unit tests: `make test`
- Specific: `make test-core`, `make test-session`, `make test-events`
- Integration: `make test-integration` (needs `GOAUTH_TEST_DSN` env var)
- Coverage: `make test-coverage-html` (opens HTML report)
- Verbose: `make test-verbose`

## Build

- Build: `make build`
- Lint: `make lint` (golangci-lint)
- Clean: `make clean`
- Always run `make build` to catch compilation errors before committing.

## Before You Build Anything
**When asked to implement or change something, STOP and think through these before writing code:**
**Surface this thinking to the user before coding.** Say what the change enables, what it costs, and what adjacent concerns it raises. Then discuss then build.

## Current State

Branch: `mvp-cleaning`. Active work on notification module refactor and template system. See `SCRATCHPAD.md` for session-persistent progress notes.
