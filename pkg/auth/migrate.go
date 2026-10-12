package auth

import (
	"context"
	"crypto/sha256"
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

// collectPending gathers all unapplied migrations across all modules, sorted by dependency order then version.
func (a *Auth) collectPending(dialect types.DialectType, appliedSet map[string]struct{}) ([]pendingMigration, error) {
	names, err := a.modulePlan()
	if err != nil {
		return nil, err
	}
	var pending []pendingMigration
	for _, name := range names {
		all := a.modules[name].Migrations()
		if len(all) == 0 {
			continue
		}
		migrations, found := all[dialect]
		if !found {
			return nil, fmt.Errorf("module %s has no %s migrations", name, dialect)
		}
		migrations = append([]types.VersionedMigration(nil), migrations...)
		sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
		seen := map[int]bool{}
		for _, m := range migrations {
			if seen[m.Version] {
				return nil, fmt.Errorf("duplicate migration version %s:%d", name, m.Version)
			}
			seen[m.Version] = true
			if len(m.Up) == 0 {
				return nil, fmt.Errorf("empty migration %s:%d", name, m.Version)
			}
			if _, applied := appliedSet[migrationKey(name, m.Version)]; applied {
				continue
			}
			pending = append(pending, pendingMigration{moduleName: name, version: m.Version, name: m.Name, up: m.Up, down: m.Down})
		}
	}
	return pending, nil
}

// ApplyMigrations applies pending versioned migrations directly (reads embedded SQL, no file I/O).
// Migrations are applied per-module in version order. Each applied migration is recorded individually.
func (a *Auth) ApplyMigrations(ctx context.Context) error {
	coordinator, ok := a.storage.(types.CoordinatedMigrationApplier)
	if !ok {
		return fmt.Errorf("automatic migrations require coordinated storage; use generated SQL with your migration runner")
	}
	return coordinator.WithMigrationLock(ctx, func(applier types.MigrationApplier) error {
		atomic, ok := applier.(types.AtomicMigrationApplier)
		if !ok {
			return fmt.Errorf("storage requires atomic migration recording")
		}
		if err := applier.EnsureMigrationsTable(ctx); err != nil {
			return err
		}
		applied, err := applier.AppliedMigrations(ctx)
		if err != nil {
			return err
		}
		dialect := applier.Dialect()
		for _, record := range applied {
			if record.Dirty {
				return fmt.Errorf("migration %s:%d is dirty; repair before startup", record.ModuleName, record.Version)
			}
			module, exists := a.modules[record.ModuleName]
			if !exists {
				continue
			}
			for _, m := range module.Migrations()[dialect] {
				if m.Version == record.Version && record.Checksum != "" && record.Checksum != fmt.Sprintf("%x", sha256.Sum256(m.Up)) {
					return fmt.Errorf("migration checksum mismatch %s:%d", record.ModuleName, record.Version)
				}
			}
		}
		pending, err := a.collectPending(dialect, buildAppliedSet(applied))
		if err != nil {
			return err
		}
		for _, p := range pending {
			record := types.MigrationRecord{ID: uuid.Must(uuid.NewV7()).String(), ModuleName: p.moduleName, Version: p.version, Name: p.name, Dialect: string(dialect), AppliedAt: time.Now(), Checksum: fmt.Sprintf("%x", sha256.Sum256(p.up))}
			if err := atomic.ApplyMigration(ctx, record, p.up); err != nil {
				return fmt.Errorf("apply migration %s:%d: %w", p.moduleName, p.version, err)
			}
		}
		return nil
	})
}

// GenerateMigrationFiles checks the goauth_migrations tracking table, collects all
// unapplied versioned migrations, and writes combined up/down SQL files.
//
// Up file: migrations in dependency + version order.
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

	pending, err := a.collectPending(dialect, appliedSet)
	if err != nil {
		return nil, err
	}
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
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.initialized.Load() || a.closed {
		return fmt.Errorf("rollback requires a separate, inactive migration instance")
	}
	a.registryMu.RLock()
	defer a.registryMu.RUnlock()
	coordinator, ok := a.storage.(types.CoordinatedMigrationApplier)
	if !ok {
		return fmt.Errorf("rollback requires coordinated storage")
	}
	module, exists := a.modules[moduleName]
	if !exists {
		return fmt.Errorf("module %q is not registered", moduleName)
	}
	if _, err := a.modulePlan(); err != nil {
		return err
	}
	return coordinator.WithMigrationLock(ctx, func(applier types.MigrationApplier) error {
		reverter, ok := applier.(types.AtomicMigrationReverter)
		if !ok {
			return fmt.Errorf("storage requires atomic migration rollback")
		}
		applied, err := applier.AppliedMigrations(ctx)
		if err != nil {
			return err
		}
		var latest *types.MigrationRecord
		for _, record := range applied {
			if record.Dirty {
				return fmt.Errorf("migration %s:%d is dirty; repair before rollback", record.ModuleName, record.Version)
			}
			if record.ModuleName == moduleName && (latest == nil || record.Version > latest.Version) {
				copy := record
				latest = &copy
			}
			if other, ok := a.modules[record.ModuleName]; ok && record.ModuleName != moduleName {
				for _, dependency := range other.Dependencies() {
					if dependency == moduleName {
						return fmt.Errorf("rollback dependent module %s before %s", record.ModuleName, moduleName)
					}
				}
			}
		}
		if latest == nil {
			return fmt.Errorf("no applied migrations for module %q", moduleName)
		}
		for _, migration := range module.Migrations()[applier.Dialect()] {
			if migration.Version != latest.Version {
				continue
			}
			if len(migration.Down) == 0 {
				return fmt.Errorf("no down migration for %s:%d", moduleName, latest.Version)
			}
			if latest.Checksum != "" && latest.Checksum != fmt.Sprintf("%x", sha256.Sum256(migration.Up)) {
				return fmt.Errorf("migration checksum mismatch %s:%d", moduleName, latest.Version)
			}
			return reverter.RevertMigration(ctx, *latest, migration.Down)
		}
		return fmt.Errorf("missing migration %s:%d", moduleName, latest.Version)
	})
}

// MigrationStatus returns all rows from the goauth_migrations tracking table.
func (a *Auth) MigrationStatus(ctx context.Context) ([]types.MigrationRecord, error) {
	applier, ok := a.storage.(types.MigrationApplier)
	if !ok {
		return nil, fmt.Errorf("storage does not implement MigrationApplier")
	}
	return applier.AppliedMigrations(ctx)
}
