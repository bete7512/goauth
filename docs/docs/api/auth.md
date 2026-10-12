---
id: api-auth
title: Auth Lifecycle
sidebar_label: Auth
sidebar_position: 1
---

# Auth Lifecycle

GoAuth follows **New → Use → Initialize → Shutdown**. Configuration is copied at construction; configure the application before initialization rather than mutating the original config afterward.

Provide `Core: &config.CoreConfig{}` even when all Core options are false. The current signup handler dereferences `Config.Core`; leaving it nil can panic on signup. The complete quickstart supplies it explicitly.

## Phase 1: Create

```go
a, err := auth.New(cfg)
if err != nil {
    return err
}
defer a.Close()
```

`cfg` is a populated `*config.Config`; see the [complete setup](../quickstart.md). `New` validates it, creates shared services, and auto-registers Core. `Config()` returns a defensive copy. Supplied service objects, storage, and backends remain application-provided dependencies; their implementations must support the concurrency they receive.

## Phase 2: Register Modules

```go
for _, module := range []config.Component{
    session.New(&config.SessionModuleConfig{EnableSessionManagement: true}),
    twofactor.New(),
    admin.New(nil),
} {
    if err := a.Use(module); err != nil {
        return err
    }
}
```

`Use(config.Component) error` accepts the minimal `Name`/`Init` contract and existing `config.Module` implementations. It returns an error for nil or unnamed components, duplicate names, registration after initialization/shutdown, or registering Session and Stateless together. It does not panic for those composition errors. Core is already registered.

If no auth strategy is registered, `Initialize` adds Stateless. Registering an OAuth or passkey module does not replace the chosen credential strategy.

## Phase 3: Initialize

```go
if err := a.Initialize(ctx); err != nil {
    return err
}
```

Initialization:

1. Selects the credential strategy and computes deterministic dependency order.
2. Checks missing dependencies, cycles, required capabilities, and conflicts.
3. Resolves shared credential storage and installs the common authentication completer.
4. Checks durable-event storage capabilities when enabled.
5. Applies or exports migrations according to configuration.
6. Initializes modules, registers hooks, and installs middleware.
7. Builds routes and rejects missing middleware, duplicate names, and method/path collisions.
8. Starts the event backend and optional outbox drain, then marks the instance ready.

Calling `Initialize` again is an error. Initialization failure shuts down started resources; construct a new instance after fixing the cause. Keep the initialization context alive for the runtime lifetime, since background services use its cancellation.

## Serving Routes

```go
mux := http.NewServeMux()
stdhttp.Register(mux, a)
```

`Routes()` returns a middleware-wrapped route snapshot after initialization, and nil before it. Route handlers enforce `MaxRequestBodyBytes` (default 1 MiB), `MaxConcurrentRequests` (default 128), and an optional `Admission` controller. Capacity exhaustion or a closed instance returns HTTP 503. These are admission limits, not per-user rate limiting.

The optional `Observer` receives built-in route names, elapsed time, and a success flag. Host routes wrapped only in `RequireAuth` do not automatically receive all the route admission/body-limit wrappers.

## Protecting Routes

```go
mux.Handle("GET /private", a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    principal, ok := types.PrincipalFromContext(r.Context())
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    fmt.Fprintln(w, principal.UserID)
})))
```

`RequireAuth` validates an **access** credential and current stored account state. It checks token version, active/required-verification state, live session when applicable, and current selected-organization membership. It adds a `types.Principal` and the compatibility context values used by existing handlers.

Refresh tokens and pending challenge tokens cannot authorize protected endpoints. See [credential transport](../security.md#credential-transport) for cookie/bearer policy.

## In-process Authentication

`SignIn` and `Authenticate` let a non-HTTP transport reuse the same password and credential validation paths:

```go
result, err := a.SignIn(ctx, types.SignInRequest{
    Email: "user@example.com",
    Password: password,
})
if err != nil {
    return err
}
switch result.Status {
case types.ChallengeRequired:
    // Deliver result.Challenges to the caller; no authenticated grant yet.
case types.Authenticated:
    // Deliver result.AccessToken and result.RefreshToken using your transport.
}

principal, err := a.Authenticate(ctx, accessToken)
if err != nil {
    return err
}
_ = principal.UserID
```

`SignIn` uses the selected Session or Stateless implementation and request admission. `Authenticate` performs online access validation; it does not itself acquire a request-admission slot. Neither method creates HTTP response cookies. The host transport is responsible for delivering results.

## Subscribing to Events

```go
a.On(types.EventAfterSignup, func(ctx context.Context, event *types.Event) error {
    return nil
})
```

Register handlers before `Initialize` so no startup delivery precedes registration. `On` delegates to the event bus; module-owned handlers belong in `RegisterHooks`. See [Events and deployment](../enterprise.md) for acknowledgements and durable completion events.

## OpenAPI

After initialization, call `GenerateOpenAPIDocs(types.OpenAPIConfig)` to receive a merged specification for enabled modules. Component names are namespaced to avoid schema collisions.

`OpenAPI(cfg)` adds a spec route at `cfg.Path + "/openapi.yaml"` and a UI at `cfg.Path`. Supply at least one server URL. This convenience method appends the auth `BasePath` to those server URLs; the UI path itself is not prefixed. Call it **before** registering routes with your framework adapter so the adapter sees the extra routes.

## Shutdown

Stop and drain your HTTP server first, then stop GoAuth:

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
if err := a.Shutdown(ctx); err != nil {
    return err
}
```

`Shutdown` marks the instance unavailable, cancels background work, calls module shutdown methods in reverse initialization order, stops the event backend, and closes storage unless `BorrowStorage` is true. It attempts all cleanup and joins errors. Repeated shutdown returns the stored result. `Close()` is the convenience form with a ten-second context.
