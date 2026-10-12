---
slug: jwt-security-best-practices
title: JWT Security in GoAuth
authors: [goauth-team]
tags: [security, jwt, best-practices, go]
---

# JWT Security in GoAuth

GoAuth validates more than a JWT signature. Its current authentication path combines purpose-bound credentials with current user, session, and organization state. This article is updated for the current checkout; use the [Security guide](/docs/security) for detailed configuration.

<!-- truncate -->

## Signing and key rotation

HS256 remains the default. RS256 uses an RSA key of at least 2048 bits; ES256 uses P-256. The active algorithm and key ID select signing material. Retained keys permit overlap during rotation and require an explicit expiration. Unknown or expired key IDs are rejected.

The public `GET /auth/.well-known/jwks.json` route exposes asymmetric public keys under the configured base path. HMAC secrets are never published; an HS256-only configuration returns 404. `JwtSecretKey` is still required for shared security helpers even when JWT signing is asymmetric.

Validation checks the configured issuer and audience, expiration, credential purpose, and consistent user identity. Proof tokens and refresh credentials cannot be used as access credentials.

## Access and refresh credentials

Access tokens default to 15 minutes. Refresh credentials default to seven days. The Session strategy uses an opaque refresh secret stored as a hash. Stateless uses a signed refresh token with a stored nonce. Both rotate refresh state conditionally so a previously used credential cannot rotate it again.

Session refresh preserves the session's identity and absolute lifetime. Stateless rotation preserves the stored refresh grant's expiry rather than extending it indefinitely. The legacy `RefreshTokenRotation` flag does not disable rotation in the current Stateless service.

Token versions revoke credentials when security state changes. Stateless logout is user-wide, rather than a single-device logout. For device-level management, use [Session](/docs/modules/session).

## Current-state checks

A valid signature is only one step. The built-in middleware loads the user, compares token version, checks activity and required contact verification, and validates the associated session when present. Selected organization context requires current membership in an active organization with a recognized role.

For non-HTTP integration use `a.Authenticate`. Its verified principal includes user, session, methods, authentication time, and selected organization. Do not turn decoded but unverified claims into a trusted principal.

## Password and lockout policy

Passwords default to 8–72 **bytes**, with no trimming or Unicode normalization. Bcrypt cannot accept a password exceeding 72 bytes. The cost defaults to 10 through `Security.HashSaltLength`.

Account lockout must be explicitly enabled:

```go
Lockout: types.LockoutConfig{
    Enabled: true,
    MaxAttempts: 5,
    LockoutDuration: 15 * time.Minute,
},
```

This is a fragment of `types.SecurityConfig`. Account lockout is distinct from network rate limiting. The runtime's admission limit bounds concurrent work; it is not a per-IP request-rate policy.

## Encryption and client transport

The manager derives an AES-256-GCM key from `EncryptionKey` and supports retained decryption keys. Use independent random secrets and plan overlap when rotating persisted encrypted material.

`AuthMode` controls bearer, cookie, or both transports independently of the selected credential strategy. Conflicting credential sources are rejected. Cookie-only JSON endpoints still return token fields; successful cookie-only redirect flows omit the token fragment. Configure secure cookies for HTTPS and CSRF protection for cookie-authenticated browser traffic.

See [Security](/docs/security), [Session](/docs/modules/session), [Stateless](/docs/modules/stateless), and [Upgrading](/docs/upgrade) for the exact configuration and compatibility changes.
