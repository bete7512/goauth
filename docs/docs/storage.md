---
id: storage
title: Storage and Repository Contracts
description: What a custom GoAuth storage has to provide. Feature stores, transactions across stores, the operations that must be atomic, and who closes the connection.
---

# Storage and Repository Contracts

**Using PostgreSQL, MySQL or SQLite through the bundled GORM storage? You can skip this page.** It already does everything described here; [Installation](installation.md#connect-a-database) shows how to connect it.

Read on if you are writing your own storage or combining stores. Custom storage has to provide the interfaces each feature asks for, and the **atomic behavior** the sign-in flows rely on. That second part is what keeps a refresh token from being used twice.

## Feature stores

`types.Storage` hands each module its own typed store: Core, Session, Stateless, Admin, OAuth, TwoFactorAuth, Passkeys, AuditLog, Invitation, Organization, IDP, RBAC and Team, plus `DB` and `Close`.

Core (users and tokens) is required. A store for a module you do not use can return nil.

`types.StorageSet` assembles separate stores into one `Storage`:

```go
store := &types.StorageSet{
    CoreStore: myCoreStore,
    SessionStore: mySessionStore,
    PasskeyStore: myPasskeyStore,
}
```

`StorageSet` does not close the stores unless you set `CloseFunc`. It also does **not** provide a transaction across them or coordinate migrations, so by itself it is not enough for every built-in operation.

## One transaction across stores

```go
type TransactionalStorage interface {
    WithTransaction(context.Context, func(types.Storage) error) error
}
```

Some operations change several features at once and must fully happen or not at all. Inside the callback, every store must be bound to the **same** transaction; a transaction on Core plus a separate one on Organizations is not enough.

These flows need it:

- accepting an invitation;
- changing an OAuth identity;
- the final step of resuming a sign-in;
- with `DurableEvents` on: Core sign-up, password reset and change, and contact verification.

Inside a transaction, use only the callback's stores, and make network calls after the commit. GoAuth's own operations hold their events until the commit, or write them to the outbox when `DurableEvents` is on.

## Operations that must be atomic

| Interface / method | Required semantics |
| --- | --- |
| `TokenRepository.MarkAsUsed` | Consume only a live, unused record; concurrent losers return `models.ErrConflict` |
| `TokenRepository.IncrementAttempts` | Increment attempts atomically and return the new count |
| `models.TokenRotator.Rotate` | Consume the expected live token and commit its replacement together |
| `models.SessionRotator.RotateToken` | Conditional refresh-secret replacement preserving logical session identity and absolute expiry |
| `models.UserCredentialMutator` | Targeted revocation, password replacement, and login activity updates |
| `models.UserAuthenticationMutator` | Targeted failed-login and contact-verification updates |
| `models.UserProfileMutator` | Restrict profile updates and atomically revoke grants on recovery-phone changes |
| `PasskeyRepository.UpdateSignCount` | Advance a nonzero counter conditionally; allow zero-to-zero for counterless credentials |

- **The rotating interfaces are optional in Go, but the refresh and resume flows require them** and return an error without them. Do not substitute "read, then delete, then create": two requests arriving together would both succeed.
- **The targeted user updates prevent lost updates.** Writing back a whole user row could undo a password change, a suspension or a revocation made in the meantime.
- **Return `models.ErrNotFound` for a missing record and `models.ErrConflict` for a conditional write that lost.**
- **A query for a live token must always apply** the expected purpose, owner, expiry and use state.

The [Models reference](api/models.md) has the current method signatures.

## Replacing one feature's store

`CoreConfig.CustomStorage`, `StatelessModuleConfig.CustomStorage` and `SessionModuleConfig.CustomStorage` replace the store for one feature. GoAuth resolves them into one shared credential store before any module starts and rejects conflicting owners, so issuing a token and validating it never use different stores by accident.

- A separate custom store does not carry the transaction and outbox abilities of the main storage. For transactional flows, provide the complete store through `Config.Storage`.
- OAuth rejects its per-feature overrides for this reason.
- Magic Link and Passkeys still have `CustomStorage` fields. Keep their records and the shared sign-in path on consistent stores; an override does not make two stores atomic.

## Who closes the storage

- By default, `Auth.Shutdown` closes `Config.Storage`.
- Set `BorrowStorage: true` when your application owns the connection.
- If `auth.New` returns an error, ownership was not transferred. Close the store yourself in that path.

## Durable events

`DurableEvents: true` needs `types.TransactionalStorage` and `types.OutboxStore`, with the outbox available inside the transaction callback. An outbox row must commit with the change it describes, and rows are claimed and acknowledged with conditional leases. See [Events and deployment](enterprise.md).

## Migrations

| To do this | Storage must implement |
| --- | --- |
| Generate SQL, read status | `MigrationApplier` |
| Apply migrations automatically | `CoordinatedMigrationApplier`, and a connection-bound `AtomicMigrationApplier` |
| Roll back | The coordinated applier above, and `AtomicMigrationReverter` |

See [Migrations](migrations.md).
