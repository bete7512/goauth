## Architecture Overview

This project follows a modular architecture:

- Core is auto-registered by `pkg/auth.New` and provides base models, routes, and services
- Optional modules (e.g., `twofactor`, `csrf`, `captcha`, `ratelimiter`, `notification`, `magiclink`) are added via `auth.Use(...)` before `Initialize`
- Storage is pluggable via `pkg/config.Storage` with implementations under `internal/storage/{gorm|mongo|sqlc}` registering module repositories
- Middlewares are managed centrally and applied by route name via the middleware manager
- Events are emitted via a centralized event bus supporting sync and async backends

### Minimal Setup

```go
store, _ := storage.NewStorage(config.StorageConfig{ Driver: "gorm", Dialect: "sqlite", DSN: "auth.db", AutoMigrate: true })
a, _ := auth.New(&config.Config{ Storage: store, AutoMigrate: true, Security: config.SecurityConfig{ JwtSecretKey: "...", EncryptionKey: "..." } })
// a.Use(twofactor.New(&twofactor.TwoFactorConfig{...})) // optional
_ = a.Initialize(context.Background())
for _, r := range a.Routes() { mux.Handle(r.Path, r.Handler) }
```

For storage architecture details, see `/.dir/Readmes/STORAGE_ARCHITECTURE.md`.
