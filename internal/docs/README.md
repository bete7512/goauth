## Architecture Overview

This project follows a modular architecture:

- Core is auto-registered by `pkg/auth.New` and provides user management, verification, and password flows
- Login/logout/refresh are handled by either the **Session** or **Stateless** module (mutually exclusive; stateless is default)
- Optional modules (e.g., `twofactor`, `csrf`, `captcha`, `notification`, `admin`, `audit`, `magiclink`, `oauth`) are added via `auth.Use(...)` before `Initialize`
- Storage uses a typed hierarchy: `types.Storage` with sub-storages (`Core()`, `Session()`, `OAuth()`, etc.) — no string-based lookups
- GORM storage implementation lives under `storage/gorm/` with sub-packages per module
- Middlewares are managed centrally and applied by route name via the middleware manager
- Events are emitted via a centralized event bus supporting sync and async backends
- Framework adapters live in `pkg/adapters/` (stdhttp, gin, chi, fiber)

### Minimal Setup

```go
store, _ := storage.NewGormStorage(storage.GormConfig{Dialect: types.DialectTypeSqlite, DSN: "auth.db"})
a, _ := auth.New(&config.Config{Storage: store, AutoMigrate: true, Security: types.SecurityConfig{JwtSecretKey: "...", EncryptionKey: "..."}})
// a.Use(twofactor.New(&twofactor.TwoFactorConfig{...})) // optional
_ = a.Initialize(context.Background())
mux := http.NewServeMux()
stdhttp.Register(mux, a)
```
