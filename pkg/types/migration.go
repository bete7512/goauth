package types

import (
	"context"
	"time"
)

// MigrationFiles holds the up and down SQL (or driver-specific script) for one dialect.
type MigrationFiles struct {
	Up   []byte
	Down []byte
}

// ModuleMigrations maps a DialectType to its migration files.
// Modules with no DB tables return an empty map.
type ModuleMigrations map[DialectType]MigrationFiles

// MigrationRecord represents one applied migration tracked in the goauth_migrations table.
type MigrationRecord struct {
	ID         string    `json:"id"`
	ModuleName string    `json:"module_name"`
	Dialect    string    `json:"dialect"`
	AppliedAt  time.Time `json:"applied_at"`
	Status     string    `json:"status"` // "up" | "down"
}

// MigrationApplier is implemented by storage backends that support the module migration system.
// Checked via type assertion: if applier, ok := storage.(types.MigrationApplier); ok { ... }
// Only GORM storage implements this initially; future backends (MongoDB, sqlc) may implement it too.
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

	// RemoveMigrationRecord deletes a migration record by module name (used on rollback).
	RemoveMigrationRecord(ctx context.Context, moduleName string) error
}
