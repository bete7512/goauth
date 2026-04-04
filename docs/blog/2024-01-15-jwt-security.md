---
slug: jwt-security-best-practices
title: JWT Security in GoAuth
authors: [goauth-team]
tags: [security, jwt, best-practices, go]
---

# JWT Security in GoAuth

This post covers how GoAuth handles JWT security -- the signing approach, token lifecycle, refresh token rotation, and the protective measures built into the library.

<!-- truncate -->

## Signing and Algorithms

GoAuth uses **HS256** (HMAC-SHA256) for JWT signing. The secret key is configured via `SecurityConfig.JwtSecretKey` and must be at least 32 characters. The library validates algorithm headers on every token parse to prevent algorithm confusion attacks.

```go
a, _ := auth.New(&config.Config{
    Storage: store,
    Migration: config.MigrationConfig{Auto: true},
    Security: types.SecurityConfig{
        JwtSecretKey:  os.Getenv("JWT_SECRET"),       // min 32 chars
        EncryptionKey: os.Getenv("ENCRYPTION_KEY"),   // for AES-256-GCM
    },
})
```

## Access and Refresh Token Pair

GoAuth issues two tokens on login:

- **Access token** -- Short-lived (default 15 minutes). Carries user claims. Used for API authorization.
- **Refresh token** -- Longer-lived (default 7 days). Used only to obtain a new access token.

The TTLs are configurable:

```go
Security: types.SecurityConfig{
    JwtSecretKey: os.Getenv("JWT_SECRET"),
    Session: types.SessionConfig{
        AccessTokenTTL:  15 * time.Minute,
        RefreshTokenTTL: 7 * 24 * time.Hour,
    },
},
```

## Refresh Token Rotation

How refresh tokens are secured depends on the authentication strategy:

**Stateless module**: Each refresh token includes a JTI (JWT ID) nonce. The JTI is stored in the database. When a refresh token is used, the old JTI is invalidated and a new token with a fresh JTI is issued. This provides one-time-use semantics -- replaying an old refresh token fails.

**Session module**: Refresh tokens are hashed with SHA-256 before storage. The raw token is only returned to the client; the database never holds the plaintext. On refresh, the incoming token is hashed and compared against the stored hash.

## Account Lockout

GoAuth includes brute-force protection via account lockout:

- **Max attempts**: 5 failed login attempts (configurable)
- **Lockout window**: 15 minutes (configurable)
- **Lockout behavior**: Returns a `429` status with time remaining until unlock

This is configured via `Config.Validate()` defaults or explicitly:

```go
Lockout: types.LockoutConfig{
    MaxAttempts:     5,
    LockoutDuration: 15 * time.Minute,
},
```

## Password Policy

GoAuth enforces password requirements at the config level:

- Minimum length: 8 characters (default)
- Maximum length: 128 characters (default)
- Configurable via `PasswordPolicy` in the config

Passwords are hashed with **bcrypt**. The cost factor is configurable through `SecurityConfig`.

## Encryption of Sensitive Data

Beyond passwords and JWTs, GoAuth encrypts sensitive fields using AES-256-GCM:

- TOTP secrets stored in the database
- OAuth provider tokens

The encryption key is set via `SecurityConfig.EncryptionKey` (32 characters for AES-256).

## Token Storage on the Client

GoAuth sets tokens in HTTP-only, secure cookies with `SameSite` attributes when using the session module. For stateless JWT, tokens are returned in JSON response bodies for the client to store as appropriate.

## What GoAuth Does Not Do

To set expectations clearly:

- **No RS256/ES256** -- GoAuth uses HS256 only. If you need asymmetric signing, you would need to implement a custom security manager satisfying the `types.SecurityManager` interface.
- **No built-in rate limiting middleware** -- Account lockout handles brute-force at the application level. For network-level rate limiting, use your reverse proxy or a dedicated middleware.
- **No token blacklisting for access tokens** -- Access tokens are short-lived by design. The stateless module blacklists refresh token JTIs on revocation.

## Security Checklist

Before deploying:

- [ ] Set `JwtSecretKey` to a strong, random 32+ character value from environment variables
- [ ] Set `EncryptionKey` to a separate strong, random 32-character value
- [ ] Configure appropriate `AccessTokenTTL` (shorter is safer; 15 minutes is a good default)
- [ ] Enable HTTPS in production (GoAuth sets `Secure` flag on cookies)
- [ ] Enable account lockout (on by default)
- [ ] Enable email verification if your app requires confirmed email addresses
- [ ] Use the CSRF module for browser-based applications
- [ ] Review audit logs regularly if using the audit module

---

_For more details, see the [Stateless Module](/docs/modules/stateless) and [Session Module](/docs/modules/session) documentation._
