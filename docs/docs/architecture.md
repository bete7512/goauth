---
id: architecture
title: Architecture Guide
sidebar_label: Architecture
sidebar_position: 3
---

# Architecture Guide

This guide explains how GoAuth is built internally. Read this if you want to contribute, build a custom module, or understand the design decisions behind the library.

## High-Level Overview

GoAuth is a **modular, framework-agnostic authentication library** for Go. It is not a standalone service — it embeds into your application. Everything is built around a plugin system where modules register themselves with a central `Auth` instance.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Your Application                             │
│                                                                     │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                      GoAuth Library                         │   │
│   │                                                             │   │
│   │   ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌───────────┐   │   │
│   │   │  Core   │  │ Session │  │ 2FA      │  │ OAuth     │   │   │
│   │   │ Module  │  │ Module  │  │ Module   │  │ Module    │   │   │
│   │   └────┬────┘  └────┬────┘  └────┬─────┘  └─────┬─────┘   │   │
│   │        │             │            │              │          │   │
│   │   ┌────┴─────────────┴────────────┴──────────────┴─────┐   │   │
│   │   │              Shared Infrastructure                  │   │   │
│   │   │  EventBus · SecurityManager · Middleware · Logger   │   │   │
│   │   └────────────────────────┬────────────────────────────┘   │   │
│   │                            │                                │   │
│   │   ┌────────────────────────┴────────────────────────────┐   │   │
│   │   │                 Storage Layer                        │   │   │
│   │   │         GORM (Postgres · MySQL · SQLite)             │   │   │
│   │   └─────────────────────────────────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Package Layout

```
goauth/
├── pkg/                    ← Public API (what consumers import)
│   ├── auth/               ← Auth instance, lifecycle (New → Use → Initialize)
│   ├── config/             ← Config structs, Module interface
│   ├── models/             ← Data models + repository interfaces
│   ├── types/              ← Shared types (events, storage, errors, security)
│   ├── modules/            ← Proxy packages (thin wrappers around internal/)
│   │   ├── session/
│   │   ├── invitation/
│   │   ├── organization/
│   │   └── ...
│   └── adapters/           ← Framework adapters (stdhttp, gin, etc.)
│
├── internal/               ← Implementation (not importable externally)
│   ├── modules/            ← Module implementations
│   │   ├── core/           ← Signup, login, password, verification
│   │   │   ├── module.go
│   │   │   ├── handlers/
│   │   │   ├── services/
│   │   │   ├── middlewares/
│   │   │   ├── docs/openapi.yml
│   │   │   └── migrations/
│   │   ├── session/
│   │   ├── invitation/
│   │   └── ...
│   ├── events/             ← EventBus + worker pool
│   ├── security/           ← JWT, hashing, encryption
│   └── middleware/          ← Global middleware manager
│
├── storage/                ← Storage backends
│   └── gorm/               ← GORM implementation
│       ├── core/
│       ├── session/
│       ├── invitation/
│       ├── organization/
│       └── ...
│
├── cli/                    ← Developer tools
│   └── goauth-gen/         ← Stub generator CLI
│
└── docs/                   ← Documentation site (Docusaurus)
```

**Key rule:** `pkg/` never leaks `internal/` types. All public-facing types live in `pkg/types/` or `pkg/models/`. The `pkg/modules/` proxy packages re-export internal module constructors with clean signatures.

## Three-Phase Lifecycle

Every GoAuth application follows this sequence:

```mermaid
graph LR
    A["auth.New(config)"] -->|1. Create| B["auth.Use(module)"]
    B -->|2. Register| B
    B -->|3. Initialize| C["auth.Initialize(ctx)"]
    C --> D["Ready to serve"]

    style A fill:#e1f5fe
    style B fill:#fff3e0
    style C fill:#e8f5e9
    style D fill:#f3e5f5
```

### Phase 1: `auth.New(config)`
- Validates config, creates logger, event bus, security manager
- Auto-registers the **Core module** (always required)
- Returns `*Auth` — not yet usable

### Phase 2: `auth.Use(module)`
- Registers modules one at a time
- Validates dependencies (e.g., 2FA requires Core)
- **Panics if called after Initialize**
- Session and Stateless are mutually exclusive

### Phase 3: `auth.Initialize(ctx)`
- Runs migrations (if `Migration.Auto: true`)
- Calls `Init()` on every registered module (creates services, handlers)
- Registers event hooks
- Collects routes from all modules
- If no auth module registered, defaults to Stateless

## Module Contract

Every module implements this 8-method interface:

```go
type Module interface {
    Name() string                                          // Unique identifier
    Init(ctx context.Context, deps ModuleDependencies) error // Initialize with shared deps
    Routes() []RouteInfo                                   // HTTP endpoints
    Middlewares() []MiddlewareConfig                        // Middleware definitions
    RegisterHooks(events EventBus) error                   // Event subscriptions
    Dependencies() []string                                // Required module names
    OpenAPISpecs() []byte                                  // Embedded OpenAPI YAML
    Migrations() ModuleMigrations                          // Per-dialect SQL migrations
}
```

All modules receive the same `ModuleDependencies` struct during `Init()`:

```
ModuleDependencies
├── Storage            ← Type-safe storage (Storage.Core(), Storage.Session(), etc.)
├── Config             ← Global config
├── Logger             ← Structured logger
├── Events             ← Event bus for pub/sub
├── MiddlewareManager  ← Register middleware
├── SecurityManager    ← JWT, hashing, encryption
├── AuthInterceptors   ← Hook into login flow (2FA challenges, org claims)
└── Options            ← Module-specific options
```

## Module Dependency Graph

```mermaid
graph TD
    Core["Core<br/><small>signup, login, password, verification</small>"]

    Session["Session<br/><small>cookie-based auth</small>"]
    Stateless["Stateless<br/><small>JWT refresh tokens</small>"]

    TwoFactor["Two-Factor<br/><small>TOTP + backup codes</small>"]
    OAuth["OAuth<br/><small>Google, GitHub, etc.</small>"]
    MagicLink["Magic Link<br/><small>passwordless email</small>"]
    Admin["Admin<br/><small>user CRUD</small>"]
    Audit["Audit<br/><small>event logging</small>"]
    Invitation["Invitation<br/><small>platform invites</small>"]
    Organization["Organization<br/><small>multi-tenant</small>"]
    Notification["Notification<br/><small>email/SMS delivery</small>"]
    Captcha["Captcha<br/><small>bot protection</small>"]
    CSRF["CSRF<br/><small>token protection</small>"]

    Core --> Session
    Core --> Stateless
    Core --> TwoFactor
    Core --> OAuth
    Core --> MagicLink
    Core --> Admin
    Core --> Audit
    Core --> Invitation
    Core --> Organization
    Core --> Notification
    Core --> CSRF

    style Core fill:#4CAF50,color:#fff
    style Session fill:#FF9800,color:#fff
    style Stateless fill:#FF9800,color:#fff
    style Notification fill:#9C27B0,color:#fff

    linkStyle default stroke:#999
```

All modules depend on **Core** (auto-registered). **Session** and **Stateless** are mutually exclusive — registering both panics. **Notification** is a pure delivery layer with no routes.

## Request Flow

How an HTTP request flows through GoAuth:

```mermaid
sequenceDiagram
    participant Client
    participant Mux as HTTP Mux
    participant MW as Middleware Chain
    participant Handler
    participant Service
    participant Repo as Repository
    participant DB as Database
    participant Events as Event Bus

    Client->>Mux: POST /auth/signup
    Mux->>MW: Route matched → apply middleware
    MW->>MW: RequestID → Auth (skip for public) → ...
    MW->>Handler: Request with context
    Handler->>Handler: Parse & validate DTO
    Handler->>Service: service.Signup(ctx, req)
    Service->>Repo: repo.Create(ctx, user)
    Repo->>DB: INSERT INTO users ...
    DB-->>Repo: OK
    Repo-->>Service: user
    Service->>Events: EmitAsync(EventAfterSignup, userData)
    Events-->>Events: Notification hook → send welcome email
    Service-->>Handler: user, nil
    Handler-->>Client: 201 Created {user data}
```

### Middleware Priority

Higher priority = runs first:

| Priority | Middleware | Scope |
|----------|-----------|-------|
| 100 | CORS (user-provided) | External |
| 90 | RequestID | Global |
| 50 | Auth (JWT validation) | Per-route |
| 45 | Org Auth | Per-route |
| 40 | 2FA Verify | Per-route |

## Event System

GoAuth uses an async event bus for cross-module communication. Modules emit events; other modules subscribe.

```mermaid
graph LR
    subgraph Emitters
        Core["Core Module"]
        Inv["Invitation Module"]
        Org["Organization Module"]
    end

    subgraph EventBus["Event Bus (Worker Pool)"]
        Q["Async Queue<br/><small>10 workers, 1000 buffer</small>"]
    end

    subgraph Subscribers
        Notif["Notification<br/><small>sends emails/SMS</small>"]
        Audit["Audit<br/><small>logs events</small>"]
        Custom["Your Hooks<br/><small>auth.On(...)</small>"]
    end

    Core -->|EventAfterSignup| Q
    Core -->|EventAfterLogin| Q
    Inv -->|EventInvitationSent| Q
    Org -->|EventOrgInvitationSent| Q

    Q --> Notif
    Q --> Audit
    Q --> Custom

    style EventBus fill:#f5f5f5,stroke:#999
    style Notif fill:#9C27B0,color:#fff
    style Audit fill:#607D8B,color:#fff
```

**Key design:** Notification hooks for must-have emails (password reset, magic link, invitations, 2FA) are always registered. They only fire when the corresponding module emits the event. Optional emails (welcome, login alerts) have config flags.

## Storage Architecture

Storage is type-safe — each module accesses its own storage interface:

```mermaid
graph TD
    S["types.Storage"]

    S --> CS["Core()<br/>→ CoreStorage"]
    S --> SS["Session()<br/>→ SessionStorage"]
    S --> IS["Invitation()<br/>→ InvitationStorage"]
    S --> OS["Organization()<br/>→ OrganizationStorage"]
    S --> OA["OAuth()<br/>→ OAuthStorage"]
    S --> TF["TwoFactorAuth()<br/>→ TwoFactorStorage"]
    S --> AL["AuditLog()<br/>→ AuditLogStorage"]

    CS --> UR["UserRepository"]
    CS --> TR["TokenRepository"]
    SS --> SR["SessionRepository"]
    IS --> IR["InvitationRepository"]
    OS --> OR["OrganizationRepository"]
    OS --> MR["MemberRepository"]
    OS --> OIR["OrgInvitationRepository"]
    OA --> AR["AccountRepository"]
    TF --> TFR["TwoFactorRepository"]
    TF --> BCR["BackupCodeRepository"]
    AL --> ALR["AuditLogRepository"]

    style S fill:#1976D2,color:#fff
    style CS fill:#42A5F5,color:#fff
    style SS fill:#42A5F5,color:#fff
    style IS fill:#42A5F5,color:#fff
    style OS fill:#42A5F5,color:#fff
```

**Custom storage:** Implement the repository interfaces to use any database. Use `goauth-gen storage all` to scaffold stubs:
```bash
go install github.com/bete7512/goauth/cli/goauth-gen@latest
goauth-gen storage all --output ./mystorage --package mystorage
```

## Migration System

Each module owns its migrations. They are embedded via `//go:embed` and applied per-dialect:

```
internal/modules/core/migrations/
├── postgres/
│   ├── 000_init_up.sql
│   ├── 000_init_down.sql
│   ├── 001_add_lockout_columns_up.sql
│   └── 001_add_lockout_columns_down.sql
├── mysql/
│   └── ...
└── sqlite/
    └── ...
```

Migrations are tracked in a `goauth_migrations` table. Each record stores `module_name`, `version`, `dialect`, and `applied_at`. During `Initialize()`, GoAuth compares applied versions against embedded migrations and applies any new ones in order.

**Adding a migration:** Create a new versioned file (e.g., `002_add_column_up.sql`) in each dialect directory. The module's `Migrations()` method picks it up automatically via `//go:embed migrations`.

## Invitation Flow (Complete)

The invitation system supports both platform invitations and org invitations. Both follow the same pattern:

```mermaid
sequenceDiagram
    participant Admin as Inviter
    participant API as GoAuth API
    participant DB as Database
    participant EB as Event Bus
    participant Email as Email Sender
    participant FE as Frontend
    participant User as Invited User

    Admin->>API: POST /invitations {email, purpose}
    API->>DB: Create invitation (token, status=pending)
    API->>EB: Emit EventInvitationSent
    EB->>Email: Send invitation email
    Email->>User: "You're invited! [Accept]"
    API-->>Admin: 201 Created

    Note over User,FE: User clicks link in email

    User->>FE: Opens https://app.com/invite?token=xxx
    FE->>FE: Shows accept form

    alt New user (no account)
        FE->>API: POST /invitations/accept {token, name, password}
        API->>DB: Create user (email from invitation)
        API->>DB: Mark invitation accepted
        API-->>FE: {access_token, refresh_token, is_new_user: true}
    else Existing user
        FE->>API: POST /invitations/accept {token}
        API->>DB: Mark invitation accepted
        API-->>FE: {access_token, refresh_token, is_new_user: false}
    end

    FE-->>User: Logged in, redirected to app
```

**Key design decisions:**
- Accept/decline endpoints are **public** (no auth). The invitation token is the authorization.
- The email link points to a **frontend URL** (`CallbackURL`), not the API. The frontend orchestrates the flow.
- New users are created with `email_verified: true` (they proved ownership by receiving the email).
- Auth tokens are returned immediately — the user is logged in right after accepting.

## Auth Interceptors

Interceptors hook into the login flow to enrich JWT claims or present challenges:

```mermaid
graph LR
    Login["Login<br/>Verified"] --> I1["Org Interceptor<br/><small>priority 50</small>"]
    I1 -->|add org claims| I2["2FA Interceptor<br/><small>priority 100</small>"]
    I2 -->|2FA required?| C{Challenge?}
    C -->|No| T["Generate Tokens"]
    C -->|Yes| CH["Return Challenge<br/><small>{requires_2fa: true}</small>"]

    style Login fill:#4CAF50,color:#fff
    style T fill:#2196F3,color:#fff
    style CH fill:#FF9800,color:#fff
```

Interceptors run in priority order (higher first). Each can:
- **Add claims** to the JWT (e.g., `active_org_id`, `org_role`)
- **Return a challenge** (e.g., 2FA required) that pauses the login flow
- **Add response data** (e.g., organization list)

## Service Pattern

All modules follow the same pattern:

```go
// Exported interface — handlers depend on this
type UserService interface {
    Signup(ctx context.Context, req *dto.SignupRequest) (*models.User, *types.GoAuthError)
}

// Unexported struct — real implementation
type userService struct {
    deps     config.ModuleDependencies
    userRepo models.UserRepository
}

// Constructor returns concrete type satisfying the interface
func NewUserService(deps config.ModuleDependencies, ...) *userService {
    return &userService{deps: deps, ...}
}
```

**Error convention:** Services return `*types.GoAuthError` (not `error`). This carries an HTTP status code and error code for consistent API responses.

## Contributing a New Module

1. Create `internal/modules/yourmodule/` with `module.go`, `config.go`, `handlers/`, `services/`, `docs/openapi.yml`
2. Add module name constant to `pkg/types/module.go`
3. Add route names to `pkg/types/routes.go`
4. If storage needed: add interfaces to `pkg/models/`, storage interface to `pkg/types/storage.go`, GORM impl to `storage/gorm/yourmodule/`
5. If events needed: add event types to `pkg/types/events.go`, event data to `pkg/types/event_data.go`
6. Create proxy package `pkg/modules/yourmodule/`
7. Add migrations in `migrations/{postgres,mysql,sqlite}/`
8. Write tests (testify/suite + uber/mock)
9. Add OpenAPI spec

Reference implementation: `internal/modules/audit/` (simple) or `internal/modules/invitation/` (medium complexity).
