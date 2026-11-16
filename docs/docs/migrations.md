---
id: migrations
title: Migration Management
description: How GoAuth creates and updates its tables. Automatic migrations, generating SQL for review, checking status, rollback, and what happens when a migration fails.
---

# Migration Management

Every module that owns tables ships versioned SQL for PostgreSQL, MySQL and SQLite. You decide how it reaches your database:

| Approach | Good for | How |
| --- | --- | --- |
| **Automatic** | The simplest setup | `Migration.Auto: true` |
| **Generate, review, then apply** | Teams that review schema changes before they run | `GenerateMigrationFiles`, then apply |
| **Your own migration tool** | Databases managed by another migration tool | Generate the SQL and run it yourself |

Whichever you choose, finish migrating before the instance accepts requests.

## Automatic Application

```go
cfg.Migration = config.MigrationConfig{Auto: true}
```

During `Initialize`, GoAuth orders modules by dependency and migrations by version, then applies what is pending. You can also call `ApplyMigrations(ctx)` yourself.

A module with tables must have migrations for the database you use; duplicate versions and empty "up" scripts are rejected. Custom storage needs `types.CoordinatedMigrationApplier`, and its connection-bound callback needs `types.AtomicMigrationApplier`. The bundled GORM storage has both.

## Coordination and Recording

Starting several instances at once is safe. A lock makes sure two of them never migrate at the same time.

| Dialect | Coordination | SQL and tracking behavior |
| --- | --- | --- |
| PostgreSQL | Connection-bound advisory lock | Transactional migration SQL and record |
| MySQL | Named connection lock | Dirty record first, DDL, then mark clean |
| SQLite | Transactional write lock | Transactional migration plan and tracking |

Applied migrations are recorded in `goauth_migrations`: module, version, name, dialect, time, a checksum of the SQL and a "dirty" flag.

### When a migration fails

Automatic startup stops when it finds either of these:

- **A dirty record.** A migration started and did not finish.
- **A checksum mismatch.** The SQL recorded as applied differs from the SQL in this version of GoAuth.

Look at the real schema and at what failed before repairing anything, and do not clear the tracking table to get past the error. MySQL DDL commits on its own, so GoAuth cannot promise to undo a failed migration there; that is why it marks the record dirty first. Older records with an empty checksum are not checked.

## Generate SQL for Review

Create the instance and register your modules, but do not serve traffic yet:

```go
files, err := a.GenerateMigrationFiles(ctx, "./migrations/generated")
if err != nil {
    return err
}
for _, path := range files {
    fmt.Println(path)
}
```

This writes the pending migrations into `goauth_{timestamp}_up.sql` and `goauth_{timestamp}_down.sql`. The up file follows dependency and version order; the down file reverses it. With nothing pending, no files are written.

- **It needs a database.** Generation reads the tracking table, and may create it.
- **The files contain schema SQL only.** They do not update `goauth_migrations`. If another tool runs them, keep the tracking table consistent before you turn on `Auto`.
- **`Migration.OutputDir` does the same export during `Initialize`.** With `Auto: true` the migrations are applied first, so usually nothing is left to export. For review, generate before you apply.

## Status

```go
records, err := a.MigrationStatus(ctx)
if err != nil {
    return err
}
for _, record := range records {
    fmt.Println(record.ModuleName, record.Version, record.Checksum, record.Dirty)
}
```

This only reads the tracking records. It repairs nothing and does not create a missing tracking table.

## Rollback

`RollbackModule(ctx, moduleName)` undoes the latest recorded version of one module.

- Use a **separate instance** that has not been initialized or closed, with every relevant module registered.
- It refuses to run on a serving instance, with a dirty record, a checksum mismatch, no "down" SQL, or a dependent module still applied.
- Storage must support coordinated migrations and `AtomicMigrationReverter`.

Down migrations can delete data, so work out what will be lost first. The docs build never runs a rollback against an application database.

## Current Schema Additions

The current source adds:

- Core: token attempt counts, typed continuation data, and outbox storage;
- Session: grant and assurance data;
- OAuth: realm and issuer fields on external identities;
- Passkeys: credential tables.

Apply the migrations for the modules you use before you deploy code that reads these fields. See [Upgrading](upgrade.md).
