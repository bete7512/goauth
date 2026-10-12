---
id: migrations
title: Migration Management
---

# Migration Management

GoAuth embeds versioned SQL with each module. The current migration runner validates dependencies, coordinates concurrent runners, tracks checksums, and stops on dirty records.

## Automatic Application

```go
cfg.Migration = config.MigrationConfig{Auto: true}
```

During `Initialize`, modules are ordered by dependency and migrations by numeric version. Modules with no schema return no migrations. A schema-owning module must have migrations for the active dialect; duplicate versions and empty up scripts are rejected.

`ApplyMigrations(ctx)` requires storage implementing `types.CoordinatedMigrationApplier`; the connection-bound callback must also implement `types.AtomicMigrationApplier`. The built-in GORM adapter supports these contracts. Run migration management before accepting requests.

## Coordination and Recording

| Dialect | Coordination | SQL and tracking behavior |
| --- | --- | --- |
| PostgreSQL | Connection-bound advisory lock | Transactional migration SQL and record |
| MySQL | Named connection lock | Dirty record first, DDL, then mark clean |
| SQLite | Transactional write lock | Transactional migration plan and tracking |

The tracking table is `goauth_migrations`. Records include module, version, name, dialect, application time, checksum, and dirty status. Existing nonempty checksums are compared to the embedded up SQL. Legacy records with an empty checksum are not retroactively verified by that comparison.

A dirty record or checksum mismatch blocks automatic startup. Investigate the actual schema and failed operation before repair. MySQL DDL can commit independently; the runner deliberately does not claim that it can roll back every DDL failure.

## Generate SQL for Review

After creating an instance and registering the desired modules, before serving traffic:

```go
files, err := a.GenerateMigrationFiles(ctx, "./migrations/generated")
if err != nil {
    return err
}
for _, path := range files {
    fmt.Println(path)
}
```

This reads the tracking table and writes pending migrations into a combined `goauth_{timestamp}_up.sql` and `_down.sql` pair. The up file follows dependency/version order; the down file reverses it. No pending changes returns no files.

Generation requires `MigrationApplier` and may create the tracking table. It is not a database-free export. The output contains schema SQL and comments, not statements that maintain GoAuth's migration records; an external runner must keep tracking consistent before automatic migration is enabled later.

`Migration.OutputDir` requests the same export during initialization. If combined with `Auto: true`, automatic application runs first, so usually no pending SQL remains to export. Generate before application when review is the goal.

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

This returns tracking records; it does not automatically repair them or create a missing tracking table.

## Rollback

`RollbackModule(ctx, moduleName)` rolls back the latest recorded version for one registered module. Use a separate instance that has **not** been initialized or closed, with all relevant modules registered. The runner rejects rollback on a serving instance, dirty state, checksum mismatch, missing down SQL, and applied dependent modules visible to its plan.

It requires coordinated storage and `AtomicMigrationReverter`. Register the complete relevant module set and assess data loss before using down migrations. Rollback is an operational action; the docs build never runs it against an application database.

## Current Schema Additions

The current source adds Core token attempt counts, typed continuation data, and outbox storage; session grant/assurance data; OAuth external-identity realm/issuer fields; and passkey credential tables. Apply the migrations for the modules you use before upgrading code that reads these fields. See [Upgrading](upgrade.md).
