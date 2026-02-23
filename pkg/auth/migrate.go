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

// GenerateMigrationFiles checks the goauth_migrations tracking table, collects all
// modules that have not yet been applied, and writes their SQL into two combined files:
//
//	goauth_{timestamp}_up.sql   — up migrations concatenated in module-name order
//	goauth_{timestamp}_down.sql — down migrations in reverse order
//
// If every registered module is already tracked, no files are written and nil is returned.
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
	appliedSet := make(map[string]struct{}, len(applied))
	for _, r := range applied {
		appliedSet[r.ModuleName] = struct{}{}
	}

	dialect := applier.Dialect()

	// Collect pending modules in deterministic (sorted) order.
	type pendingEntry struct {
		name string
		up   []byte
		down []byte
	}
	var pending []pendingEntry
	// Sort module names for deterministic file content.
	names := make([]string, 0, len(a.modules))
	for name := range a.modules {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		module := a.modules[name]
		if _, alreadyApplied := appliedSet[name]; alreadyApplied {
			continue
		}
		files, found := module.Migrations()[dialect]
		if !found || len(files.Up) == 0 {
			continue
		}
		pending = append(pending, pendingEntry{name: name, up: files.Up, down: files.Down})
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

	// Build combined up SQL — modules in sorted order.
	var upBuf strings.Builder
	for _, p := range pending {
		fmt.Fprintf(&upBuf, "-- module: %s\n", p.name)
		upBuf.Write(p.up)
		upBuf.WriteString("\n")
	}

	// Build combined down SQL — modules in reverse order (last in, first out).
	var downBuf strings.Builder
	for i := len(pending) - 1; i >= 0; i-- {
		p := pending[i]
		fmt.Fprintf(&downBuf, "-- module: %s\n", p.name)
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

// ApplyMigrations applies pending module migrations directly (reads embedded SQL, no file I/O).
// Records each applied migration in the goauth_migrations table.
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
	appliedSet := make(map[string]struct{}, len(applied))
	for _, r := range applied {
		appliedSet[r.ModuleName] = struct{}{}
	}

	dialect := applier.Dialect()
	for _, module := range a.modules {
		if _, alreadyApplied := appliedSet[module.Name()]; alreadyApplied {
			continue
		}
		files, found := module.Migrations()[dialect]
		if !found || len(files.Up) == 0 {
			continue
		}

		a.logger.Info("Applying migration", "module", module.Name(), "dialect", string(dialect))
		if err := applier.ExecMigration(ctx, files.Up); err != nil {
			return fmt.Errorf("exec migration for %s: %w", module.Name(), err)
		}
		record := types.MigrationRecord{
			ID:         uuid.NewString(),
			ModuleName: module.Name(),
			Dialect:    string(dialect),
			AppliedAt:  time.Now(),
			Status:     "up",
		}
		if err := applier.RecordMigration(ctx, record); err != nil {
			return fmt.Errorf("record migration for %s: %w", module.Name(), err)
		}
	}
	return nil
}

// RollbackModule runs the down.sql for a specific module and removes its tracking record.
func (a *Auth) RollbackModule(ctx context.Context, moduleName string) error {
	applier, ok := a.storage.(types.MigrationApplier)
	if !ok {
		return fmt.Errorf("storage does not implement MigrationApplier")
	}
	module, exists := a.modules[moduleName]
	if !exists {
		return fmt.Errorf("module %q is not registered", moduleName)
	}
	dialect := applier.Dialect()
	files, found := module.Migrations()[dialect]
	if !found || len(files.Down) == 0 {
		return fmt.Errorf("no down migration for module %q dialect %s", moduleName, string(dialect))
	}
	a.logger.Info("Rolling back migration", "module", moduleName, "dialect", string(dialect))
	if err := applier.ExecMigration(ctx, files.Down); err != nil {
		return fmt.Errorf("exec rollback for %s: %w", moduleName, err)
	}
	return applier.RemoveMigrationRecord(ctx, moduleName)
}

// MigrationStatus returns all rows from the goauth_migrations tracking table.
func (a *Auth) MigrationStatus(ctx context.Context) ([]types.MigrationRecord, error) {
	applier, ok := a.storage.(types.MigrationApplier)
	if !ok {
		return nil, fmt.Errorf("storage does not implement MigrationApplier")
	}
	return applier.AppliedMigrations(ctx)
}
