---
id: index
title: GoAuth Documentation
sidebar_label: Overview
slug: /
---

# GoAuth Documentation

GoAuth is a modular, framework-agnostic authentication library for Go. Compose the auth features you need -- core, session or stateless JWT, passkeys, 2FA, OAuth, notifications, admin, organizations -- and plug them into any web framework.

## Getting Started

- [Introduction](/docs/intro) -- What GoAuth is and how it works
- [Installation](/docs/installation) -- Install and set up GoAuth
- [Quick Start](/docs/quickstart) -- Build a working auth system

## Modules

**Core** (auto-registered) -- User registration, profile management, password flows, email/phone verification.

**Authentication** (pick one):
- [Session](/docs/modules/session) -- Server-side sessions with cookie strategies
- [Stateless](/docs/modules/stateless) -- JWT access + refresh tokens (default)

**Optional**:
- [Passkeys](/docs/modules/passkeys) -- WebAuthn registration and sign-in
- [Notification](/docs/modules/notification) -- Email/SMS delivery
- Two-Factor -- TOTP-based 2FA with backup codes
- OAuth -- Social login (Google, GitHub, Microsoft, Discord)
- Admin -- User CRUD with admin middleware
- Invitation -- Platform invitations (beta access and referrals; signup gating is separate)
- Organization -- Multi-org support with roles and org-scoped invitations
- Audit -- Security event logging with retention policies
- Captcha -- reCAPTCHA v3, Cloudflare Turnstile
- CSRF -- Token-based CSRF protection
- Magic Link -- Passwordless auth via email

## Architecture

```
+--------------------------------------+
|         Your Application             |
+---------------+----------------------+
                |
                v
+--------------------------------------+
|  GoAuth Instance                     |
|  +--------------------------------+  |
|  |    Core Module (Auto)          |  |
|  |  Signup, Profile, Passwords,   |  |
|  |  Verification                  |  |
|  +--------------------------------+  |
|                                      |
|  Auth Strategy (pick one):           |
|  +-------------+ +--------------+   |
|  |   Session   | |  Stateless   |   |
|  +-------------+ +--------------+   |
|                                      |
|  Optional Modules:                   |
|  +-------------+ +--------------+   |
|  |Notification | |  Two-Factor  |   |
|  +-------------+ +--------------+   |
|  +-------------+ +--------------+   |
|  |   OAuth     | |   Captcha    |   |
|  +-------------+ +--------------+   |
|  +-------------+ +--------------+   |
|  |   Admin     | |    CSRF      |   |
|  +-------------+ +--------------+   |
|  +-------------+ +--------------+   |
|  |   Audit     | | Magic Link   |   |
|  +-------------+ +--------------+   |
|  +-------------+                    |
|  |Organization |                    |
|  +-------------+                    |
+--------------------------------------+
                |
                v
+--------------------------------------+
|  Storage (GORM: Postgres/MySQL/      |
|  SQLite, or custom types.Storage)    |
+--------------------------------------+
```

## Three-Phase Pattern

```go
a, err := auth.New(cfg)
if err != nil {
    return err
}
defer a.Close()
if err := a.Use(twofactor.New(nil)); err != nil {
    return err
}
if err := a.Initialize(ctx); err != nil {
    return err
}
stdhttp.Register(mux, a)
```

This is an integration fragment; see [Quick Start](quickstart.md) for a complete runnable program. These pages track the current checkout. The [Upgrade guide](upgrade.md) covers changed APIs and stored data. Both authentication strategies perform current-state checks against storage.


## Framework Integration

Built-in adapters in `pkg/adapters/`:

```go
stdhttp.Register(mux, a)         // net/http
ginadapter.Register(router, a)   // Gin
chiadapter.Register(router, a)   // Chi
fiberadapter.Register(app, a)    // Fiber
```

## Reference

- [API Endpoints](/docs/api/endpoints) -- REST API documentation
- [Core Module](/docs/modules/core) -- Core module details
- [Notification Module](/docs/modules/notification) -- Email/SMS integration

- [Security](security.md) -- Credential validation, signing keys, and rotation
- [Storage](storage.md) -- Custom storage and atomic contracts
- [Migrations](migrations.md) -- Apply, generate, and roll back schema changes
