---
id: upgrade
title: Upgrading to the Current API
seoTitle: "Upgrade GoAuth from v0.2 to the current API"
description: "How to move from GoAuth v0.2.x to the current Go API: the steps, what changed in constructors, credentials, storage and defaults, and what to test before rollout."
keywords: ["goauth upgrade", "goauth migration guide", "goauth v0.3"]
---

# Upgrading to the Current API

These docs describe the `main` branch, which can be ahead of the latest tagged release. Match the version in your `go.mod` to the source you deploy.

## Upgrading from v0.2.x

Version 0.3 changes credentials, the schema and several defaults at once. Plan a maintenance deployment, not a rolling one. The [CHANGELOG](https://github.com/bete7512/goauth/blob/main/CHANGELOG.md) lists every breaking change.

1. **Update the code.** Move to Go 1.26 and change imports to `pkg/modules/<name>`, with one config argument per constructor (see the table below).
2. **Stop the old instances.** Do not run old and new writers side by side.
3. **Migrate.** Back up the database, look at the pending migrations with `MigrationStatus`, then apply them once (`Migration.Auto` or `ApplyMigrations`).
4. **Start the new instances.** Credentials issued by v0.2.x are rejected, so every user signs in again.
5. **Review the new defaults** before going live:
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

`Initialize` now fails on missing middleware, route collisions, missing dependencies or capabilities, and conflicting storage bindings. Register Admin with Invitation and Audit. A failed initialization closes what it started; create a new instance to retry.

## Keep an Explicit Core Configuration

Keep `Core: &config.CoreConfig{}` in the top-level config even when you set no options. The sign-up handler reads this pointer, and a nil Core config makes it panic. The [Quick Start](quickstart.md) sets it.

## Credentials and Clients

**Every request is checked against current state, in both strategies:** the user and token version, plus the session or organization when they apply. Stateless and cookie caching no longer avoid database queries.

**Old tokens can be rejected.** JWTs must carry the configured issuer and audience, and the purpose and subject claims. Plan for clients to sign in again and for an overlap of signing keys.

**Refresh behaves differently in each strategy.**

- Session refresh keeps the same session ID and the same absolute expiry, and replaces the secret atomically.
- Stateless refresh always rotates the stored nonce, whatever `RefreshTokenRotation` says. The stored expiry is an absolute deadline for renewing.
- Stateless logout revokes all of the user's grants, not only the token that was presented.

**Inputs follow `AuthMode`.** When two enabled inputs carry different credentials, the request is rejected. In cookie-only mode, OAuth and magic-link redirects leave tokens out of the URL fragment, but JSON responses can still contain credentials. `AuthModeCustom` is not accepted.

## Challenges and Passkeys

Handle the `challenges` array in password, OAuth, magic-link, passkey, invitation and refresh responses: a successful proof no longer always means the user is signed in. Two-factor verification needs `temp_token` and `code`; a user ID alone is not supported.

Passkeys add begin and finish endpoints for registration and login, and credential management for users. Configure an RP ID and allowed origins, apply the passkey migrations, and use persistent ceremony storage. See [Passkeys](modules/passkeys.md).

## Storage and Schema

If you maintain custom storage, add:

- `Storage.Passkeys`,
- token attempt counting,
- atomic token consumption and rotation,
- session refresh rotation,
- targeted user updates.

The built-in security operations need a transaction across stores. Combining stores with `StorageSet` does not provide one.

Apply the new migrations for the modules you enable: Core (attempts, continuations, outbox), Session (grant data), OAuth (external identity) and Passkeys. The migration runner now needs coordinated and atomic capabilities, checks non-empty checksums, and stops on a dirty record. See [Storage](storage.md) and [Migrations](migrations.md).

## OAuth and Organizations

**OAuth**

- Provider maps are keyed by stable connection IDs.
- Microsoft needs an explicit tenant UUID.
- OpenID Connect sign-ins verify signature, issuer, audience, nonce and subject. There is no fallback to unverified userinfo.
- Browser callbacks need the state-binding cookie.
- Linking by email is opt-in and requires verified ownership.

**Organizations**

- A token carries only the selected organization. Call `/org/my` for the list of memberships; do not expect `org_memberships` in every token.
- A role GoAuth does not recognize grants no membership privileges.

## Configuration Defaults and Limits

What the code does today, which in a few places differs from what a config comment suggests:

- Password length is 8 to 72 **bytes**, not 8 to 128 characters.
- Lockout is on by default; set `Lockout.Disabled: true` to turn it off. A locked account answers `INVALID_CREDENTIALS` unless `Lockout.RevealLocked` is set.
- Magic links last ten minutes by default. Delivery can be a link, a code or both, with attempt limits.
- The session-management flag does not remove routes.
- `ChallengeTTL` is not yet applied by the passkey ceremony.
- `twofactor.verify` is not a per-route step-up middleware, and `Required` does not provide a public enrollment flow.
- The credential-cookie `Domain` is not applied by the common cookie helper.

## Validation Before Rollout

1. Run the [Quick Start](quickstart.md) to confirm the installation works.
2. Exercise the modules you use: refresh and revocation, required verification, factor challenges.
3. Run your migration plan against a copy of your deployment's database.

The docs repository checks its own rendered pages, routes, code examples and model signatures. Those checks do not replace an integration test of your application.
