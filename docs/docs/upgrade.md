---
id: upgrade
title: Upgrading to the Current API
---

# Upgrading to the Current API

These docs describe the current working-tree API, including changes that may not yet be published as a tagged release. Match your dependency version to the source you deploy. For local verification, use a Go module replacement pointing to this checkout.

## Upgrading from v0.2.x

The first beta changes credentials, schema and several defaults at once, so plan a maintenance deployment rather than a rolling one. The [CHANGELOG](https://github.com/bete7512/goauth/blob/main/CHANGELOG.md) lists every breaking change.

1. Move to Go 1.26 and update imports to `pkg/modules/<name>`, with one config argument per constructor (table below).
2. Drain old instances; do not run old and new writers side by side.
3. Back up the database, inspect pending migrations with `MigrationStatus`, then apply them once (`Migration.Auto` or `ApplyMigrations`).
4. Start the new instances. Credentials issued by v0.2.x are rejected, so every user signs in again.
5. Review the new defaults before going live:
   - rate limiting is on; set `Config.TrustedProxies` behind a load balancer, and give it a shared store for several replicas,
   - cookies are Secure; local plain-HTTP setups need `Security.Session.AllowInsecureCookies`,
   - OAuth sign-up needs a provider-verified email; Microsoft tenants need the optional `xms_edov` claim,
   - invitation links need `CallbackURL`, because tokens are stored only as digests.

Ask users with pending email-verification, password-reset or invitation links to request new ones after the upgrade.

## Constructor and Lifecycle Changes

| Earlier usage or assumption | Current API |
| --- | --- |
| `session.New(cfg, store)` | `session.New(&config.SessionModuleConfig{CustomStorage: store})` |
| `stateless.New(cfg, store)` | `stateless.New(&config.StatelessModuleConfig{CustomStorage: store})` |
| `magiclink.New(cfg, store)` | `magiclink.New(&config.MagicLinkModuleConfig{CustomStorage: store})` |
| OAuth storage options as a second argument | One config argument; independent custom OAuth stores are currently rejected; use aggregate transactional storage |
| Every extension needs eight methods | `Use` accepts minimal `config.Component`; existing `config.Module` still works |
| Composition errors panic | `Use`/`Initialize` return errors; handle them |
| Registration order controls initialization | Dependency/capability planning determines deterministic order |
| Mutate config after creation | Configure first; `New` snapshots config and `Config()` returns a copy |
| Always close storage separately | Auth closes owned storage; use `BorrowStorage` for host ownership |

Initialization now rejects missing middleware, route collisions, missing dependencies/capabilities, and conflicting storage bindings. Register Admin with Invitation and Audit. An initialization failure closes started resources; retry with a fresh instance.

## Credentials and Clients

Access validation is online for both strategies. It checks current user/token version and applicable session/organization state. Remove assumptions that Stateless or cookie caching avoids all storage queries.

JWTs now require the configured issuer/audience and credential-purpose/subject claims. Legacy credentials missing those fields can be rejected. Plan client reauthentication and signing-key overlap rather than assuming all old credentials remain valid.

Session refresh keeps the logical session ID and absolute expiry while atomically replacing its secret. Stateless refresh always rotates the stored nonce in the current implementation, regardless of the retained `RefreshTokenRotation` flag. Its stored expiry remains an absolute renewal deadline. Stateless logout revokes the user's grants, not just one presented nonce.

Cookie/bearer inputs follow `AuthMode`, and conflicting enabled inputs are rejected. Cookie-only OAuth/magic-link redirects omit token fragments, but JSON responses can still include credentials. `AuthModeCustom` is not accepted by config validation.

## Challenges and Passkeys

Handle the `challenges` array on password, OAuth, magic-link, passkey, invitation, and refresh responses. A successful proof does not necessarily mean completed authentication. Two-factor verification requires `temp_token` plus `code`; the old user-ID-only continuation is unsupported.

Passkeys add registration/login begin-and-finish endpoints and owned credential management. Configure an RP ID and allowed origins, migrate passkey tables, and use persistent ceremony storage. See [Passkeys](modules/passkeys.md).

## Storage and Schema

Update custom implementations for `Storage.Passkeys`, token attempt counting, atomic token consumption/rotation, session refresh rotation, and targeted user mutations. The current built-in security operations require aggregate transaction support; composing stores with `StorageSet` does not supply it automatically.

Apply the new Core attempt/continuation/outbox migrations, session grant-data migration, OAuth external-identity migration, and passkey migration for enabled modules. The migration runner requires coordinated/atomic capabilities, validates nonempty checksums, and blocks dirty state. See [Storage](storage.md) and [Migrations](migrations.md).

## OAuth and Organizations

Use provider maps keyed by stable connection IDs. Microsoft needs an explicit tenant UUID. OIDC verifies signatures, issuer, audience, nonce, and subject without an unverified userinfo fallback. Browser callbacks require the state-binding cookie.

Email linking is explicit and requires verified ownership. Organization claims contain only selected-org context; use `/org/my` for a membership list rather than relying on `org_memberships` in every token. Unknown roles do not grant membership privileges.

## Configuration Defaults and Limits

- Password bounds are 8–72 **bytes**, not 8–128 characters.
- Lockout is on by default; set `Lockout.Disabled: true` to turn it off. A locked account answers `INVALID_CREDENTIALS` unless `Lockout.RevealLocked` is set.
- Magic-link lifetime defaults to ten minutes; delivery supports link, code, or both with attempt limits.
- The current session-management flag does not remove routes; `ChallengeTTL` is not yet applied by the passkey ceremony implementation.
- `twofactor.verify` is not implemented as per-route step-up middleware, and `Required` does not supply a public enrollment flow.
- Credential-cookie `Domain` is not applied by the current common cookie helper.

These limits are documented so integrations reflect actual behavior rather than config comments alone.

## Validation Before Rollout

Use the [Quick Start](quickstart.md) to check installation, then exercise your selected modules, refresh/revocation, required verification, factor challenges, and migration plan against your deployment's database. The docs repository includes checks for rendered content, routes, code examples, and generated model signatures; those do not replace an application integration test.

## Explicit Core Configuration

Keep `Core: &config.CoreConfig{}` in the top-level config even when no options are enabled. The current signup handler dereferences this pointer; a nil Core config can panic. The runnable quickstart sets it explicitly.
