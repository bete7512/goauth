---
id: security
title: Security and Credentials
description: How GoAuth decides who a request belongs to, and the settings you control. Cookies and bearer tokens, token signing, key rotation, passwords, lockout and stored secrets.
---

# Security and Credentials

How GoAuth decides who a request belongs to, and the security settings you control.

## The model in one minute

GoAuth keeps three steps apart:

1. **Prove identity:** a password, an OAuth callback, a magic link, a passkey or an invitation token.
2. **Complete the sign-in:** every method hands its proof to one shared path, which checks the account's current policy and whether another factor is required. Only then are credentials issued.
3. **Authorize each request:** every protected request is checked against current state in storage, not only against the token's signature.

## Credential Transport

`Security.AuthMode` says where GoAuth reads credentials from: `types.AuthModeCookie`, `types.AuthModeBearer` or `types.AuthModeBoth` (the default).

| Mode | Access input | Refresh input | Credential cookies issued |
| --- | --- | --- | --- |
| `cookie` | Access cookie | Refresh cookie | Yes |
| `bearer` | `Authorization: Bearer ...` | JSON `refresh_token` or Bearer header | No |
| `both` | Cookie or Bearer header | Cookie, JSON, or Bearer header | Yes |

Use `cookie` for browser apps, `bearer` for API clients, and `both` only when you need both. This choice is independent of the Session or Stateless strategy.

**The cookies**

- Default names are `goauth_access_session` and `goauth_refresh_session`; the suffix is `Security.Session.Name` (default `session`).
- They are `HttpOnly` and `Secure`. `Session.AllowInsecureCookies` drops `Secure` for local plain-HTTP development, and `Initialize` logs a warning.
- They use `Session.SameSite` (default Lax) and `Session.Path` (default `/`).

**Things that may surprise you**

- Two enabled sources carrying *different* credentials, such as a cookie and a Bearer header that disagree, are rejected. Identical values are fine.
- `Session.Domain` is not applied by the current cookie helper, so cookies are host-only. `Session.MaxAge` does not override each credential's lifetime.
- Bearer-only mode issues no credential cookies, but OAuth still needs its browser-binding cookie.
- Cookie-only mode controls what is read and which cookies are set. JSON responses can still contain token fields.
- `AuthModeCustom` exists as a constant but is rejected by configuration. For your own transport, use [the in-process API](api/auth.md#in-process-authentication).

HTTPS, CSRF protection for cookie-authenticated writes ([CSRF module](modules/csrf.md)) and CORS stay your job.

## Online Access Validation

A valid signature is not enough to pass `RequireAuth`.

First the token: the configured algorithm and key, issuer, audience, a required expiry and the issued-at rules.

Then current state in storage:

- it is an access token (`type: access`) whose `sub` matches its `user_id`;
- its token version is current, so tokens from before a password change stop working;
- the user is active and has completed any required email or phone verification;
- with sessions, the session is alive, unexpired and owned by that user;
- with an `active_org_id`, the user is still a member with a recognized role, and the organization is active.

The result is the `Principal` from `types.PrincipalFromContext`: user, realm, session, organization, sign-in methods, sign-in time and expiry. Do not build equivalent trust from an unverified JWT payload. The realm is always `default` today; organization membership does not isolate identities.

## JWT Algorithms and JWKS

HS256 is the default. RS256 and ES256 let other services verify tokens without a shared secret, and need a signing key:

```go
security := types.SecurityConfig{
    JwtSecretKey: os.Getenv("JWT_SECRET_KEY"),
    EncryptionKey: os.Getenv("ENCRYPTION_KEY"),
    JWTAlgorithm: types.JWTAlgorithmRS256,
    JWTPrivateKeyFile: "/run/secrets/goauth-signing.pem",
    JWTKeyID: "signing-2026-10",
    JWTIssuer: "https://auth.example.com",
    JWTAudience: "my-api",
}
```

- `JwtSecretKey` (at least 32 bytes) is still required with RS256 or ES256, for HMAC uses other than signing. `EncryptionKey` needs at least 16 bytes.
- RSA keys must be at least 2048 bits; ES256 needs P-256.
- Inline PEM fields win over file fields. A public key you supply must match the private key; otherwise it is derived.
- An invalid key makes `auth.New` fail. There is no fallback to HS256.
- Issuer and audience default to `goauth`. Applications that share keys should use distinct values.

**The public key endpoint.** Core serves `GET {BasePath}/.well-known/jwks.json`. RS256 and ES256 return the public keys with a one-hour cache header. HS256 returns 404, because a shared secret is never published. A custom `SecurityManager` must implement the JWKS provider methods to expose keys.

**Its limit.** A service that verifies tokens through JWKS learns only that the signature is valid. It does not see a ban, a password change, a revoked session or a removed membership. Access and refresh credentials also have distinct purposes, even when one key signs both.

## Signing-Key Rotation

Make the new key active, and keep the old one for verification until its tokens expire:

```go
security.RetainedJWTKeys = []types.JWTVerificationKey{
    {
        ID: "previous-signing-key",
        Algorithm: types.JWTAlgorithmRS256,
        PublicKeyPEM: previousPublicKey,
        NotAfter: retirementTime,
    },
}
```

- A retained key needs a non-empty ID different from the active one, a supported algorithm and a retirement time.
- HS256 retained keys use `Secret`; asymmetric keys use `PublicKeyPEM`.
- Retained keys only verify. New tokens use the active key.
- An unknown, retired or algorithm-mismatched key ID is rejected.
- The public key set includes retained asymmetric keys until they retire.

Rotation is configuration, applied at startup; there is no live key-management API. Plan the overlap around token lifetime and JWKS caches downstream.

For HS256, issue tokens with a stable, non-empty `JWTKeyID` *before* switching secrets. Older tokens without a key ID cannot select a retained key.

## Encryption Rotation

The default manager encrypts with AES-GCM, using a key derived from `EncryptionKey` with SHA-256. Each ciphertext records its key ID.

To rotate, set `EncryptionKeyID` for the active secret and keep earlier ID-to-secret pairs in `DecryptionKeys` while stored values or pending sign-ins still need them.

- Only fields passed through the manager are encrypted, such as stored provider credentials and sealed ceremony data. It is not encryption of every column.
- There is no automatic re-encryption. Migrating data and retiring keys is up to you.

## Passwords and Lockout

**Passwords**

- Length is measured in **bytes**: 8 to 72 by default, bcrypt's input limit. A higher maximum is capped at 72.
- Input is not trimmed, normalized or truncated.
- Optional rules require uppercase, lowercase, digits and special characters.
- The bcrypt cost comes from `HashSaltLength` (default 10).

**Lockout**

- On by default: 5 failed attempts lock the account for 15 minutes. `Lockout.Disabled: true` turns it off. Assigning `Lockout.Enabled` has no effect; it is derived during validation.
- A locked account answers `INVALID_CREDENTIALS`, like a wrong password, so lockout reveals neither that an account exists nor that locking it worked. `Lockout.RevealLocked: true` answers `ACCOUNT_LOCKED` (423) instead.
- Timing reveals nothing either: the password is still checked while locked, and an unknown identifier costs one password hash.

Change passwords through GoAuth's password flows. Direct repository writes skip these rules.

## Stored Secrets

Single-use secrets are stored as digests, so a database read or a leaked backup yields nothing that can be redeemed.

| Secret | Stored as |
| --- | --- |
| Email-verification, password-reset, magic-link and invitation tokens | SHA-256 digest (`s1:` prefix), looked up by digest |
| Six-digit codes for password reset, phone verification and magic-link sign-in | HMAC-SHA256 digest (`h1:` prefix), keyed from `Security.JwtSecretKey` and bound to the token row |
| Refresh tokens and pending sign-ins | Digests |

The codes use a keyed digest because a plain hash of six digits is reversed by trying a million values.

- The raw value exists only in the delivered link or message. A lost invitation is re-sent, not re-read.
- Invitation links need `CallbackURL`, or `InvitationCallbackURL` for organizations.
- Rotating `JwtSecretKey` invalidates codes in flight, which live an hour at most.
- Tokens and codes issued before digests were introduced stay usable until they expire. A submitted value shaped like a stored digest is never looked up as a plain token.

## Authentication Challenges

A challenge, such as a second factor, blocks credentials at login, at refresh and when resuming.

- The pending token is bound to its purpose and stored on the server. It cannot authorize a protected endpoint.
- The 2FA step needs `temp_token` and `code`, limits attempts, and consumes the pending sign-in atomically before issuing credentials. See [Two-Factor](modules/twofactor.md).
- Refresh preserves the original sign-in time and verified methods.
- Extensions cannot replace the reserved identity, purpose, lifetime, session or assurance claims.
- Signing rejects a claims payload larger than 4096 bytes.

## Operational Controls

- Built-in routes limit concurrent requests (128 by default) and request bodies (1 MiB by default).
- `AdmissionController` and `OperationObserver` plug in shared capacity limits and telemetry.
- Neither replaces endpoint-specific abuse prevention or your application's authorization.
- The [Audit module](modules/audit.md) records the events you configure. Check which events your flows emit and how delivery is guaranteed before relying on it; see [Events and deployment](enterprise.md).
