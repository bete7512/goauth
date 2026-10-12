---
id: storage
title: Storage and Repository Contracts
---

# Storage and Repository Contracts

The built-in GORM adapter implements the current repository, transaction, migration, and outbox capabilities for PostgreSQL, MySQL, and SQLite. Custom storage must provide both the feature interfaces and the atomic behavior required by the flows you enable.

## Feature Stores

`types.Storage` exposes Core, Session, Stateless, Admin, OAuth, TwoFactorAuth, Passkeys, AuditLog, Invitation, and Organization stores, plus `DB` and `Close`. Modules request their own interfaces; unsupported optional stores can return nil. Core user and token storage are required.

`types.StorageSet` adapts separate implementations to that aggregate interface:

```go
store := &types.StorageSet{
    CoreStore: myCoreStore,
    SessionStore: mySessionStore,
    PasskeyStore: myPasskeyStore,
}
```

The stores are borrowed unless `CloseFunc` is provided. `StorageSet` alone does **not** implement an aggregate transaction or migration coordinator. It can compose capabilities, but is not sufficient for every built-in security operation.

## Aggregate Transactions

```go
type TransactionalStorage interface {
    WithTransaction(context.Context, func(types.Storage) error) error
}
```

The callback must expose all participating feature stores bound to the **same transaction**. Invitation acceptance, OAuth identity mutation, and final authentication resumption use transaction-bound operations. Core signup, password reset/change, and contact verification enter the aggregate transaction wrapper when `DurableEvents` is enabled. A transaction on Core plus an independent transaction on Organizations cannot make a cross-feature mutation atomic.

Use only the callback's stores during a transaction. External email or network calls belong after commit. The built-in operation wrapper defers async events until commit, or appends them to the transactional outbox when `DurableEvents` is enabled.

## Atomic Repository Capabilities

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

The rotating repository interfaces are optional Go capabilities but required by their refresh/resume flows. Missing capabilities produce errors; do not substitute a non-atomic read/delete/create sequence. Targeted user mutation interfaces prevent stale whole-user writes from undoing concurrent password, suspension, or revocation changes.

Use `models.ErrNotFound` for an absent record and `models.ErrConflict` for failed conditional writes. Query methods that select a live token must consistently apply the expected purpose, ownership, expiry, and use-state rules. The [Models reference](api/models.md) contains the current method signatures.

## Shared Credential Stores

`CoreConfig.CustomStorage`, `StatelessModuleConfig.CustomStorage`, and `SessionModuleConfig.CustomStorage` participate in shared store resolution. Conflicting owners are rejected before module initialization so token issuance and access validation cannot silently use different stores.

Independent custom credential overrides do not preserve aggregate transaction/outbox capabilities automatically. For transactional flows, expose the complete store through `Config.Storage` instead. OAuth currently rejects all three of its custom per-feature storage overrides and requires this aggregate approach.

Magic Link and Passkeys still expose feature-specific `CustomStorage` fields. Ensure their proof records and the shared completer use consistent stores; a constructor accepting an override does not imply cross-store atomicity.

## Storage Ownership

By default, `Auth.Shutdown` closes `Config.Storage`. Set `BorrowStorage: true` if the host application owns the connection and closes it separately. If `auth.New` fails, ownership was not transferred; close the newly created store in that error path.

## Durable Events

`DurableEvents: true` requires aggregate `types.TransactionalStorage` and `types.OutboxStore`, including outbox capability inside the transaction callback. An outbox row must commit with its associated mutation. Claiming and acknowledging rows must use conditional leases. See [Events and deployment](enterprise.md).

## Migrations

Automatic migrations require `CoordinatedMigrationApplier` and a connection-bound `AtomicMigrationApplier`. Rollback requires `AtomicMigrationReverter`. Implementing only the original `MigrationApplier` interface is sufficient for SQL generation/status, not automatic application. See [Migration management](migrations.md).
