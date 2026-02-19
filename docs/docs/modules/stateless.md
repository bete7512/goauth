---
id: stateless
title: Stateless Module
sidebar_label: Stateless
sidebar_position: 4
---

# Stateless Module

JWT-based stateless authentication. This is the **default** — if no auth module is explicitly registered, Stateless is used. Mutually exclusive with [Session](session.md).

## Features

- JWT access + refresh tokens
- Refresh token rotation
- Token blacklisting via nonce storage

## Registration

```go
import "github.com/bete7512/goauth/internal/modules/stateless"

a.Use(stateless.New(&config.StatelessModuleConfig{
    RefreshTokenRotation: true,
}, nil))
```

Or just don't register any auth module — Stateless is the default.

## Configuration

```go
type StatelessModuleConfig struct {
    // Rotate refresh tokens on each refresh (default: false)
    RefreshTokenRotation bool
}
```

Token TTLs are set in `SecurityConfig.Session`:

```go
Security: types.SecurityConfig{
    Session: types.SessionConfig{
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 7 * 24 * time.Hour,
    },
}
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/login` | — | Authenticate, returns JWT tokens |
| POST | `/logout` | ✓ | Blacklist current token |
| POST | `/refresh` | — | Get new access token (optionally rotates refresh token) |
