package types

import (
	"context"
	"time"
)

// VersionedMigration represents a single numbered migration step for one dialect.
// Modules embed multiple versioned migrations (000_init, 001_add_roles, etc.).
type VersionedMigration struct {
	Version int    // 0, 1, 2, ... parsed from filename prefix
	Name    string // human-readable name parsed from filename (e.g. "init", "add_roles")
	Up      []byte
	Down    []byte
}

// ModuleMigrations maps a DialectType to its ordered list of versioned migrations.
// Modules with no DB tables return an empty map.
type ModuleMigrations map[DialectType][]VersionedMigration

// MigrationRecord represents one applied migration tracked in the goauth_migrations table.
type MigrationRecord struct {
	Checksum   string    `json:"checksum"`
	Dirty      bool      `json:"dirty"`
	ID         string    `json:"id"`
	ModuleName string    `json:"module_name"`
	Version    int       `json:"version"`
	Name       string    `json:"name"`
	Dialect    string    `json:"dialect"`
	AppliedAt  time.Time `json:"applied_at"`
}

// CoordinatedMigrationApplier serializes migration runners across processes.
// The callback must use only the supplied, connection-bound applier.
type CoordinatedMigrationApplier interface {
	WithMigrationLock(context.Context, func(MigrationApplier) error) error
}

// AtomicMigrationApplier commits SQL and its checksum record together where
// transactional DDL exists. Other dialects must persist a dirty record first
// and require operator repair after an interrupted or failed DDL operation.
type AtomicMigrationApplier interface {
	ApplyMigration(context.Context, MigrationRecord, []byte) error
}

// AtomicMigrationReverter applies the same atomic/dirty-record guarantees on rollback.
type AtomicMigrationReverter interface {
	RevertMigration(context.Context, MigrationRecord, []byte) error
}

// MigrationApplier is implemented by storage backends that support the module migration system.
// Checked via type assertion: if applier, ok := storage.(types.MigrationApplier); ok { ... }
type MigrationApplier interface {
	// Dialect returns the current DB dialect ("postgres", "mysql", "sqlite", ...)
	Dialect() DialectType

	// EnsureMigrationsTable creates the goauth_migrations tracking table if it does not exist.
	EnsureMigrationsTable(ctx context.Context) error

	// AppliedMigrations returns all rows from the goauth_migrations table.
	AppliedMigrations(ctx context.Context) ([]MigrationRecord, error)

	// ExecMigration executes a raw SQL script (multiple statements separated by ";").
	ExecMigration(ctx context.Context, sql []byte) error

	// RecordMigration inserts a migration record into goauth_migrations.
	RecordMigration(ctx context.Context, record MigrationRecord) error

	// RemoveMigrationRecord deletes a migration record by module name and version.
	RemoveMigrationRecord(ctx context.Context, moduleName string, version int) error
}
