---
id: index
title: GoAuth Documentation
sidebar_label: Overview
slug: /
---

# GoAuth Documentation

GoAuth is a modular, framework-agnostic authentication library for Go. Compose the auth features you need -- core, session or stateless JWT, 2FA, OAuth, notifications, admin, organizations -- and plug them into any web framework.

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
- [Notification](/docs/modules/notification) -- Email/SMS delivery
- Two-Factor -- TOTP-based 2FA with backup codes
- OAuth -- Social login (Google, GitHub, Microsoft, Discord)
- Admin -- User CRUD with admin middleware
- Invitation -- Standalone invitations (invite-only registration, beta access, referrals)
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
// 1. Create
a, _ := auth.New(&config.Config{...})

// 2. Register optional modules
a.Use(twofactor.New(&config.TwoFactorConfig{...}))

// 3. Initialize
a.Initialize(context.Background())

// Serve with adapter
mux := http.NewServeMux()
stdhttp.Register(mux, a)
```

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
