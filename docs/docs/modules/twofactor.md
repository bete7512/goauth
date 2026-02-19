---
id: twofactor
title: Two-Factor Module
sidebar_label: Two-Factor
sidebar_position: 5
---

# Two-Factor Module

TOTP-based two-factor authentication with backup codes. Intercepts the login flow — when a user with 2FA enabled logs in, they receive a temporary token and must complete verification via `/2fa/verify-login`.

## Features

- TOTP (Time-based One-Time Password) via authenticator apps
- QR code URL for easy setup
- Backup codes for recovery
- Login flow interception via event hooks
- Optional enforcement for all users

## Registration

```go
import "github.com/bete7512/goauth/internal/modules/twofactor"

a.Use(twofactor.New(&twofactor.TwoFactorConfig{
    Issuer:           "MyApp",      // Shown in authenticator app
    Required:         false,         // Force 2FA for all users
    BackupCodesCount: 10,
    CodeLength:       8,
}))
```

## How It Works

1. User calls `POST /2fa/setup` → gets secret + QR URL
2. User scans QR in authenticator app
3. User calls `POST /2fa/verify` with TOTP code → 2FA enabled
4. On next login, login returns `requires_2fa: true` + `temp_token`
5. User calls `POST /2fa/verify-login` with temp token + TOTP code → gets auth tokens

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/2fa/setup` | ✓ | Start 2FA setup, returns secret + QR URL |
| POST | `/2fa/verify` | ✓ | Verify TOTP code, enables 2FA |
| POST | `/2fa/disable` | ✓ | Disable 2FA |
| GET | `/2fa/status` | ✓ | Get 2FA status |
| POST | `/2fa/verify-login` | — | Complete login with TOTP code |

## Configuration

```go
type TwoFactorConfig struct {
    Issuer           string  // App name in authenticator (default: "GoAuth")
    Required         bool    // Make 2FA mandatory for all users
    BackupCodesCount int     // Number of backup codes (default: 10)
    CodeLength       int     // Backup code length (default: 8)
}
```
