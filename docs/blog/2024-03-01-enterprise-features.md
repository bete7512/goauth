---
slug: enterprise-authentication-features
title: Enterprise-Ready Features in GoAuth
authors: [goauth-team]
tags: [enterprise, security, compliance, organizations, audit]
---

# Enterprise-Ready Features in GoAuth

GoAuth includes several modules and capabilities aimed at organizations that need more than basic signup/login. This post covers what is available today for multi-tenant setups, compliance, and advanced security.

<!-- truncate -->

## Organization Module

The organization module provides multi-org support:

- **Create organizations** with metadata and settings
- **Role-based membership** -- assign roles (owner, admin, member, or custom) to users within an organization
- **Invitations** -- invite users to organizations via email with configurable expiration
- **Multiple memberships** -- users can belong to multiple organizations

```go
import "github.com/bete7512/goauth/pkg/modules/organization"

a.Use(organization.New(nil))
```

The organization module adds its own API endpoints for creating orgs, managing members, sending invitations, and switching organization context.

## Audit Logging

The audit module tracks security-relevant events across your system:

- Login attempts (successful and failed)
- Password changes and resets
- 2FA enrollment and verification
- Admin actions on user accounts
- Session creation and revocation

Each audit entry includes timestamp, actor ID, action, IP address, user agent, and severity level.

### Retention Policies

Audit logs support configurable retention with automatic cleanup:

```go
import "github.com/bete7512/goauth/pkg/modules/audit"

a.Use(audit.New(&audit.Config{
    RetentionDays: 90,
    CleanupInterval: 24 * time.Hour,
}))
```

The cleanup runs as a background goroutine that respects context cancellation for graceful shutdown.

## Two-Factor Authentication

GoAuth's 2FA implementation includes:

- **TOTP** (RFC 6238) with configurable issuer, digits, and period
- **Encrypted secret storage** -- TOTP secrets are encrypted with AES-256-GCM before being written to the database
- **Backup codes** -- configurable count (default 10) and length (default 8 characters)
- **Code reuse prevention** -- each TOTP code can only be used once within its validity window
- **Sync intercept** -- during login, 2FA verification is enforced via `EmitSync` so the login flow blocks until the code is verified

```go
import "github.com/bete7512/goauth/pkg/modules/twofactor"

a.Use(twofactor.New(&config.TwoFactorConfig{
    Issuer:           "MyCompany",
    BackupCodesCount: 10,
    CodeLength:       8,
}))
```

## OAuth with PKCE

The OAuth module supports 4 providers -- Google, GitHub, Microsoft, and Discord -- with PKCE (Proof Key for Code Exchange) for secure authorization code flows:

```go
import "github.com/bete7512/goauth/pkg/modules/oauth"

a.Use(oauth.New(&config.OAuthModuleConfig{
    Providers: []config.OAuthProvider{
        {
            Name:         "google",
            ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
            ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
            RedirectURL:  "https://app.example.com/auth/oauth/google/callback",
        },
    },
}, nil))
```

## Event Hooks

GoAuth's event system supports enterprise integration patterns:

- **Multiple handlers per event** -- attach several handlers to the same event type
- **Priority ordering** -- handlers execute in priority order (higher priority runs first)
- **Retry policies** -- configure retries for failed event handlers
- **Dead-letter queue** -- events that exhaust retries are sent to a DLQ for inspection
- **Custom async backend** -- replace the default in-memory worker pool with your own `types.AsyncBackend` implementation (e.g., backed by a message queue)

```go
a.On(types.EventAfterSignup, func(ctx context.Context, data interface{}) error {
    // sync new user to external systems
    return nil
})
```

## Pluggable Storage

GoAuth's storage layer is interface-based:

- **Built-in**: GORM backend supporting PostgreSQL, MySQL, and SQLite
- **Cache decorator**: In-memory cache for reducing database load
- **Custom backends**: Implement `types.Storage` (with `Core()`, `Session()`, `Stateless()` sub-interfaces) to use any data store

This means you can use GoAuth with existing enterprise databases or non-SQL backends without forking the library.

## What GoAuth Does Not Provide

To be clear about scope:

- **No SAML or LDAP** -- GoAuth handles OAuth 2.0 for social login. For SAML/LDAP, integrate at the identity provider level and use GoAuth for session management.
- **No RBAC system** -- The organization module has roles for org membership. For application-level permissions, implement your own authorization layer on top of GoAuth's user/org identities.
- **No built-in Redis or RabbitMQ** -- The `AsyncBackend` and storage interfaces are pluggable, but GoAuth does not ship with Redis or message queue implementations. The in-memory worker pool and GORM storage are the built-in defaults.
- **No Prometheus metrics or Kubernetes operators** -- GoAuth is a library, not a service. Instrument it with your existing observability stack.

## Getting Started

Add the modules you need:

```go
a.Use(organization.New(nil))
a.Use(audit.New(&audit.Config{RetentionDays: 90}))
a.Use(twofactor.New())
a.Use(oauth.New(&config.OAuthModuleConfig{...}, nil))
```

See the [Examples](/docs/showcase) page for complete setup patterns and the individual module docs for configuration details.

---

_Follow development on [GitHub](https://github.com/bete7512/goauth)._
