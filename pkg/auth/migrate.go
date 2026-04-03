package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// migrationKey uniquely identifies an applied migration.
func migrationKey(moduleName string, version int) string {
	return fmt.Sprintf("%s:%d", moduleName, version)
}

// buildAppliedSet returns a set of "module:version" keys from applied records.
func buildAppliedSet(applied []types.MigrationRecord) map[string]struct{} {
	set := make(map[string]struct{}, len(applied))
	for _, r := range applied {
		set[migrationKey(r.ModuleName, r.Version)] = struct{}{}
	}
	return set
}

// pendingMigration is a single migration step waiting to be applied.
type pendingMigration struct {
	moduleName string
	version    int
	name       string
	up         []byte
	down       []byte
}

// collectPending gathers all unapplied migrations across all modules, sorted by module name then version.
func (a *Auth) collectPending(dialect types.DialectType, appliedSet map[string]struct{}) []pendingMigration {
	// Sort module names for deterministic order.
	names := make([]string, 0, len(a.modules))
	for name := range a.modules {
		names = append(names, name)
	}
	sort.Strings(names)

	var pending []pendingMigration
	for _, name := range names {
		module := a.modules[name]
		migrations, found := module.Migrations()[dialect]
		if !found {
			continue
		}
		for _, m := range migrations {
			if _, applied := appliedSet[migrationKey(name, m.Version)]; applied {
				continue
			}
			if len(m.Up) == 0 {
				continue
			}
			pending = append(pending, pendingMigration{
				moduleName: name,
				version:    m.Version,
				name:       m.Name,
				up:         m.Up,
				down:       m.Down,
			})
		}
	}
	return pending
}

// ApplyMigrations applies pending versioned migrations directly (reads embedded SQL, no file I/O).
// Migrations are applied per-module in version order. Each applied migration is recorded individually.
func (a *Auth) ApplyMigrations(ctx context.Context) error {
	applier, ok := a.storage.(types.MigrationApplier)
	if !ok {
		return fmt.Errorf("storage does not implement MigrationApplier")
	}
	if err := applier.EnsureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}
	applied, err := applier.AppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("get applied migrations: %w", err)
	}
	appliedSet := buildAppliedSet(applied)
	dialect := applier.Dialect()

	pending := a.collectPending(dialect, appliedSet)
	for _, p := range pending {
		a.logger.Info("Applying migration", "module", p.moduleName, "version", p.version, "name", p.name, "dialect", string(dialect))
		if err := applier.ExecMigration(ctx, p.up); err != nil {
			return fmt.Errorf("exec migration %s v%d (%s): %w", p.moduleName, p.version, p.name, err)
		}
		record := types.MigrationRecord{
			ID:         uuid.Must(uuid.NewV7()).String(),
			ModuleName: p.moduleName,
			Version:    p.version,
			Name:       p.name,
			Dialect:    string(dialect),
			AppliedAt:  time.Now(),
		}
		if err := applier.RecordMigration(ctx, record); err != nil {
			return fmt.Errorf("record migration %s v%d: %w", p.moduleName, p.version, err)
		}
	}
	return nil
}

// GenerateMigrationFiles checks the goauth_migrations tracking table, collects all
// unapplied versioned migrations, and writes combined up/down SQL files.
//
// Up file: migrations in module-name + version order.
// Down file: migrations in reverse order.
func (a *Auth) GenerateMigrationFiles(ctx context.Context, outputDir string) ([]string, error) {
	applier, ok := a.storage.(types.MigrationApplier)
	if !ok {
		return nil, fmt.Errorf("storage does not implement MigrationApplier")
	}
	if err := applier.EnsureMigrationsTable(ctx); err != nil {
		return nil, fmt.Errorf("ensure migrations table: %w", err)
	}
	applied, err := applier.AppliedMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("get applied migrations: %w", err)
	}
	appliedSet := buildAppliedSet(applied)
	dialect := applier.Dialect()

	pending := a.collectPending(dialect, appliedSet)
	if len(pending) == 0 {
		return nil, nil
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	timestamp := time.Now().Format("20060102150405")
	upPath := filepath.Join(outputDir, fmt.Sprintf("goauth_%s_up.sql", timestamp))
	downPath := filepath.Join(outputDir, fmt.Sprintf("goauth_%s_down.sql", timestamp))

	// Build combined up SQL — modules in sorted order, then version order.
	var upBuf strings.Builder
	for _, p := range pending {
		fmt.Fprintf(&upBuf, "-- module: %s  version: %d  name: %s\n", p.moduleName, p.version, p.name)
		upBuf.Write(p.up)
		upBuf.WriteString("\n")
	}

	// Build combined down SQL — reverse order.
	var downBuf strings.Builder
	for i := len(pending) - 1; i >= 0; i-- {
		p := pending[i]
		fmt.Fprintf(&downBuf, "-- module: %s  version: %d  name: %s\n", p.moduleName, p.version, p.name)
		downBuf.Write(p.down)
		downBuf.WriteString("\n")
	}

	if err := os.WriteFile(upPath, []byte(upBuf.String()), 0644); err != nil {
		return nil, fmt.Errorf("write up file: %w", err)
	}
	if err := os.WriteFile(downPath, []byte(downBuf.String()), 0644); err != nil {
		return nil, fmt.Errorf("write down file: %w", err)
	}
	return []string{upPath, downPath}, nil
}

// RollbackModule rolls back the latest applied migration for a module.
// Call repeatedly to roll back multiple versions.
func (a *Auth) RollbackModule(ctx context.Context, moduleName string) error {
	applier, ok := a.storage.(types.MigrationApplier)
	if !ok {
		return fmt.Errorf("storage does not implement MigrationApplier")
	}
	module, exists := a.modules[moduleName]
	if !exists {
		return fmt.Errorf("module %q is not registered", moduleName)
	}

	// Find the highest applied version for this module.
	applied, err := applier.AppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("get applied migrations: %w", err)
	}
	latestVersion := -1
	for _, r := range applied {
		if r.ModuleName == moduleName && r.Version > latestVersion {
			latestVersion = r.Version
		}
	}
	if latestVersion < 0 {
		return fmt.Errorf("no applied migrations found for module %q", moduleName)
	}

	// Find the down SQL for that version.
	dialect := applier.Dialect()
	migrations, found := module.Migrations()[dialect]
	if !found {
		return fmt.Errorf("no migrations for module %q dialect %s", moduleName, string(dialect))
	}
	var downSQL []byte
	for _, m := range migrations {
		if m.Version == latestVersion {
			downSQL = m.Down
			break
		}
	}
	if len(downSQL) == 0 {
		return fmt.Errorf("no down migration for module %q version %d", moduleName, latestVersion)
	}

	a.logger.Info("Rolling back migration", "module", moduleName, "version", latestVersion, "dialect", string(dialect))
	if err := applier.ExecMigration(ctx, downSQL); err != nil {
		return fmt.Errorf("exec rollback for %s v%d: %w", moduleName, latestVersion, err)
	}
	return applier.RemoveMigrationRecord(ctx, moduleName, latestVersion)
}

// MigrationStatus returns all rows from the goauth_migrations tracking table.
func (a *Auth) MigrationStatus(ctx context.Context) ([]types.MigrationRecord, error) {
	applier, ok := a.storage.(types.MigrationApplier)
	if !ok {
		return nil, fmt.Errorf("storage does not implement MigrationApplier")
	}
	return applier.AppliedMigrations(ctx)
}
