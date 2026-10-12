---
id: stateless
title: Stateless Module
sidebar_label: Stateless
sidebar_position: 4
---

# Stateless Module

Stateless uses JWT access credentials and JWT refresh credentials with persistent nonce records. It is the default strategy if neither Session nor Stateless is explicitly registered. It does not create session records, but the built-in access boundary still checks current user state in storage.

## Registration

```go
if err := a.Use(stateless.New(&config.StatelessModuleConfig{
    RefreshTokenRotation: true,
})); err != nil {
    return err
}
```

Import `pkg/modules/stateless` and `pkg/config`. `stateless.New(nil)` is valid. Registering it alongside Session returns an error.

## Configuration

| Field | Effective behavior |
| --- | --- |
| `CustomStorage` | Optional `types.CoreStorage`, resolved as the shared core store |
| `RefreshTokenRotation` | Retained field; the current refresh implementation always rotates credentials, even when false |

Access TTL defaults to 15 minutes and refresh TTL to 7 days under `Security.Session`. Algorithms HS256, RS256, and ES256 are supported; see [Signing and rotation](../security.md).

## Access Validation

Protected routes and `Auth.Authenticate` validate the JWT's algorithm, signature, issuer, audience, expiry, subject, and `type: access`. They then load the user and verify token version, active status, required contact verification, and selected-organization membership when present.

This provides online revocation. It is **not** a zero-database-query authentication path. A downstream verifier using only JWKS cannot observe user suspension, token-version changes, or membership changes without an additional current-state check.

## Endpoints

All paths use `BasePath` (default `/auth`).

| Method | Path | Credential | Description |
| --- | --- | --- | --- |
| POST | `/login` | Password | Complete authentication or return pending challenges |
| POST | `/refresh` | Refresh credential | Rotate nonce and return a new pair, or return a challenge |
| POST | `/logout` | Access credential | Increment the user's token version and delete their token records |

Stateless logout is user-wide: it revokes existing access credentials through the version check and removes refresh nonces. It is not limited to the presented refresh token.

## Refresh Token Rotation (JTI/Nonce Mechanism)

1. Successful completion issues a JWT refresh credential with `type: refresh`, `sub`, `user_id`, `token_version`, and a random `jti`.
2. Core token storage saves the JTI as a `refresh_nonce` record and saves grant context in the private `Data` field.
3. Refresh validates both the signed credential and the live nonce record, including owner, purpose, expiry, and current user policy.
4. Interceptors reevaluate policy using persisted authentication methods, original authentication time, and organization context.
5. `models.TokenRotator.Rotate` atomically consumes the expected record and creates its replacement. Only one concurrent caller succeeds.

The replacement retains the original stored expiry. Although the new JWT has a new signed expiration time, the server also checks the stored nonce deadline; refreshing does not create an unlimited renewal lifetime.

### Token storage

The `tokens` table stores active refresh nonces, not the complete refresh JWT. `Data` preserves `types.GrantContext` and is excluded from JSON. Invalid or consumed nonces cannot renew credentials. Pending authentication continuations use a different purpose and cannot be supplied as access or refresh credentials.

## Custom Token Storage

```go
if err := a.Use(stateless.New(&config.StatelessModuleConfig{
    CustomStorage: myCoreStore,
    RefreshTokenRotation: true,
})); err != nil {
    return err
}
```

Implement `models.TokenRotator` as well as `models.TokenRepository`; a delete followed by an unrelated insert is not sufficient. Atomic account mutations and transactional completion have additional [storage requirements](../storage.md).

## Event Hooks

Password login has before/after hooks and audit-related events. Subscribe before initialization with `a.On`. OAuth, magic link, passkeys, and invitations share the completion boundary while retaining their own event behavior; see [Events](../enterprise.md).

## Next Steps

- [Session](session.md)
- [Two-Factor](twofactor.md)
- [Security and credentials](../security.md)
