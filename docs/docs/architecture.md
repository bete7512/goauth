---
id: architecture
title: Architecture Guide
sidebar_label: Architecture
sidebar_position: 3
---

# Architecture

GoAuth is a library embedded in your Go process. Modules share configuration, storage, events, middleware, and an authentication completion service. The public entry points live in `pkg/`; application integrations do not import `internal/`.

## Repository Structure

```text
pkg/auth/           Lifecycle, routes, in-process sign-in, migrations, OpenAPI
pkg/config/         Config, Component, Module, composition contracts
pkg/types/          Public security, storage, events, principal and grant types
pkg/models/         Persistence models and repository interfaces
pkg/modules/        Public constructors for built-in modules
pkg/adapters/       net/http plus separately versioned Gin/Chi/Fiber adapters
internal/authentication/  Shared completion and challenge resumption
internal/operation/       Transaction-bound security operations and events
internal/modules/         Built-in handlers, services, migrations and OpenAPI
internal/security/        Signing, encryption, credentials and current-state checks
storage/gorm/       SQL repositories, transactions, migration locks and outbox
docs/               Next.js + Fumadocs website; authored guides in docs/docs/
```

## Three-Phase Lifecycle

```mermaid
graph LR
    A["auth.New(config)"] -->|1. Create| B["auth.Use(module)"]
    B -->|2. Register| B
    B -->|3. Initialize| C["auth.Initialize(ctx)"]
    C --> D["Ready to serve"]
    D --> E["auth.Shutdown(ctx)"]
    style A fill:#e1f5fe
    style B fill:#fff3e0
    style C fill:#e8f5e9
    style D fill:#f3e5f5
```

### Phase 1: `auth.New(config)`

Validates and snapshots configuration, creates shared services, and registers Core. `Config()` returns a copy. New instances cannot serve protected routes until initialization completes.

### Phase 2: `auth.Use(module)`

Registers a `config.Component` and returns an error for invalid/duplicate names, conflicting Session/Stateless strategies, or registration after initialization. These are errors, not panics.

### Phase 3: `auth.Initialize(ctx)`

Selects default Stateless when needed, validates the complete composition graph, resolves credential stores, sets up shared completion, applies/exports migrations, and initializes modules in dependency order. It validates the completed route/middleware table before starting event consumption and marking the instance ready.

Failed initialization cleans up started resources. Shutdown reverses module order and then closes backend/storage resources. See [Lifecycle](api/auth.md) for the API and storage ownership.

## Module Contract

The minimum extension contract has two methods:

```go
type Component interface {
    Name() string
    Init(context.Context, config.ModuleDependencies) error
}
```

This is the shape of `config.Component`; `Auth.Use` accepts it directly. The original eight-method `config.Module` contract remains supported. For a minimal component, routes, middleware, hooks, dependencies, OpenAPI, migrations, shutdown, and constraints are optional capabilities detected by the adapter.

```go
type ModuleConstraints struct {
    Provides  []string
    Requires  []string
    Conflicts []string
}
```

`Constraints()` advertises capabilities, required capabilities, and conflicting **module names**. Required providers initialize before consumers. Missing providers/dependencies, duplicate providers, cycles, and conflicts cause initialization errors. Optional `Shutdown(context.Context) error` participates in reverse-order cleanup.

Dependencies supplied to a module include `Storage`, `Config`, `Logger`, `Events`, `MiddlewareManager`, `SecurityManager`, `AuthInterceptors`, and `Completion`. Submit verified evidence to `Completion`; never populate trusted authentication evidence directly from an unverified request body.

## Module Dependency Graph

```mermaid
graph TD
    Core["Core: always registered"]
    Core --> Session["Session OR Stateless"]
    Core --> TwoFactor["Two-Factor"]
    Core --> OAuth["OAuth"]
    Core --> Passkeys["Passkeys"]
    Core --> MagicLink["Magic Link"]
    Core --> Organization["Organizations"]
    Core --> Admin["Admin"]
    Admin --> Invitation["Invitations"]
    Core --> Invitation
    Core --> Audit["Audit"]
    Admin -.->|route middleware| Audit
    Core --> Notification["Notification delivery"]
    CSRF["CSRF: no declared dependency"]
    Captcha["Captcha: no declared dependency"]
    style Core fill:#4CAF50,color:#fff
    style Session fill:#FF9800,color:#fff
```

Module names alone do not cover every requirement. Storage capabilities and referenced middleware must also exist. Invitation declares Admin as a dependency. Audit declares Core, but its admin routes also require Admin’s middleware. Notification exposes no HTTP endpoints.

## Request Flow

```mermaid
sequenceDiagram
    participant Client
    participant Adapter as HTTP adapter
    participant Guard as Admission and middleware
    participant Service
    participant Completion
    participant Store as Shared storage
    Client->>Adapter: Authentication request
    Adapter->>Guard: Wrapped route
    Guard->>Service: Bounded request
    Service->>Store: Verify proof or current credential
    Service->>Completion: Verified authentication evidence
    Completion->>Store: Check policy and persist continuation or grant
    Completion-->>Service: Authenticated or challenge required
    Service-->>Client: Response envelope and configured cookies
```

Protected access goes through online validation: cryptographic checks, credential purpose, user/version/eligibility, session validity when applicable, and selected-organization membership. The `Principal` placed in context represents that verified result. Signature-only parsing is not the built-in authorization boundary.

### Middleware Priority

Higher priorities run first. Core authentication uses priority 50; organization and session-cache middleware use 45; the Two-Factor route middleware uses 40. Its current body is a pass-through: factor enforcement is in the completion interceptor, not per-route step-up middleware. Route requirements are validated at initialization so missing protection is an error.

## Event System

```mermaid
graph LR
    Mutation["Transaction-bound operation"] --> Outbox["Outbox when DurableEvents is enabled"]
    Mutation --> Deferred["Otherwise publish after commit"]
    Outbox --> Dispatcher["Acknowledged dispatcher"]
    Deferred --> Backend["AsyncBackend"]
    Backend --> Dispatcher
    Dispatcher --> Notification["Notification handlers"]
    Dispatcher --> Audit["Audit handlers"]
    Dispatcher --> Custom["Application handlers"]
```

The default backend uses ten workers and a bounded queue of 1000. A custom `types.AsyncBackend` can supply transport; `types.AcknowledgingBackend` adds retry-aware dispatch acknowledgement. Durable operation events and `authentication.completed` use the colocated outbox. Delivery is at least once; stable event IDs help consumers deduplicate. See [Events and deployment](enterprise.md) for the exact scope.

## Storage Architecture

```mermaid
graph TD
    S["types.Storage"] --> Core["Core: users and tokens"]
    S --> Sessions["Session: sessions and grant context"]
    S --> OAuth["OAuth: external identities"]
    S --> TwoFactor["TwoFactorAuth: TOTP and backup codes"]
    S --> Passkeys["Passkeys: WebAuthn credentials"]
    S --> Organization["Organization: orgs, members, invitations"]
    S --> Invitation["Invitation: platform invitations"]
    S --> Audit["AuditLog: audit records"]
    S --> Tx["TransactionalStorage: one transaction across stores"]
    Tx --> Outbox["OutboxStore when durable events are enabled"]
```

`StorageSet` composes feature stores; it does not provide aggregate atomicity by itself. Refresh and continuation flows require conditional repository capabilities, and cross-feature security operations require transaction-bound stores. See [Storage contracts](storage.md) and [Models](api/models.md).

## Migration System

Each schema-owning module embeds versioned SQL per dialect. The runner applies dependency order followed by version order, coordinates concurrent runners, and records checksums. Dirty records and changed recorded SQL block automatic startup. PostgreSQL/SQLite support transactional recording; MySQL marks records dirty around DDL.

See [Migration management](migrations.md) for SQL generation, external-runner bookkeeping, and inactive-instance rollback.

## Invitation Flow (Complete)

```mermaid
sequenceDiagram
    participant Inviter
    participant API as GoAuth
    participant Store as Transactional storage
    participant Delivery as Notification handler
    participant User as Invited user
    Inviter->>API: Send invitation
    API->>Store: Persist invitation
    API->>Delivery: Invitation event
    Delivery->>User: Frontend acceptance link
    User->>API: Token plus new-account fields if needed
    API->>Store: Accept invitation and create user/membership atomically
    API->>API: Complete authentication under current policy
    alt More factors required
        API-->>User: Challenges and continuation
    else Complete
        API-->>User: Selected session/JWT grant
    end
```

Acceptance is public because the invitation token is the proof. Existing users omit new-account fields. Acceptance mutation and subsequent HTTP authentication completion are distinct steps: do not describe every failure after acceptance as an unconsumed invitation. A 2FA challenge can follow a successful acceptance.

## Auth Interceptors

```mermaid
graph LR
    Evidence["Verified evidence"] --> Eligibility["Current user eligibility"]
    Eligibility --> TwoFactor["2FA policy: priority 100"]
    TwoFactor --> Org["Selected organization: priority 50"]
    Org --> Decision{Challenges?}
    Decision -->|Yes| Pending["Persist purpose-bound continuation"]
    Decision -->|No| Grant["Issue selected credential grant"]
    Pending --> Resume["Verify factor and resume atomically"]
    Resume --> Eligibility
```

Interceptors run in deterministic priority order and can add non-reserved claims or response data. Challenges are honored during login, refresh, and resume. Identity/assurance claims are reserved. The organization interceptor enriches the **selected** organization after checking current membership; it does not put every membership in a token or select an organization automatically.

## Service Pattern

Built-in modules separate HTTP DTOs/handlers from service logic and persistence. `Auth.SignIn` exposes password sign-in without HTTP, and `Auth.Authenticate` returns a verified principal. Custom transports deliver credentials themselves. Extension services use the shared completer so successful proof does not skip current policy or factor requirements.
