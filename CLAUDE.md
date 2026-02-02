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

## Current State

Branch: `feat/storage-architecture-update`. Active work on storage architecture, CSRF, and captcha modules. See `SCRATCHPAD.md` for session-persistent progress notes.
