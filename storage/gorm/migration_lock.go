package gorm

import (
	"context"
	"fmt"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

func (s *GormStorage) WithMigrationLock(ctx context.Context, fn func(types.MigrationApplier) error) error {
	return s.db.WithContext(ctx).Connection(func(db *gorm.DB) error {
		bound := *s
		bound.db = db
		switch s.Dialect() {
		case types.DialectTypePostgres:
			if err := db.Exec("SELECT pg_advisory_lock(721907530)").Error; err != nil {
				return err
			}
			defer db.WithContext(context.Background()).Exec("SELECT pg_advisory_unlock(721907530)")
			return fn(&bound)
		case types.DialectTypeMysql:
			var acquired int
			if err := db.Raw("SELECT GET_LOCK('goauth_schema_migration', 30)").Scan(&acquired).Error; err != nil {
				return err
			}
			if acquired != 1 {
				return fmt.Errorf("migration lock unavailable")
			}
			defer db.WithContext(context.Background()).Exec("SELECT RELEASE_LOCK('goauth_schema_migration')")
			return fn(&bound)
		case types.DialectTypeSqlite:
			// The write lock covers the complete plan, including schema bookkeeping.
			return db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Exec("CREATE TABLE IF NOT EXISTS goauth_migration_lock (id INTEGER PRIMARY KEY)").Error; err != nil {
					return err
				}
				if err := tx.Exec("INSERT OR IGNORE INTO goauth_migration_lock (id) VALUES (1)").Error; err != nil {
					return err
				}
				if err := tx.Exec("UPDATE goauth_migration_lock SET id = id WHERE id = 1").Error; err != nil {
					return err
				}
				bound.db = tx
				return fn(&bound)
			})
		default:
			return fmt.Errorf("migration locking unsupported for %s", s.Dialect())
		}
	})
}

func (s *GormStorage) ApplyMigration(ctx context.Context, record types.MigrationRecord, sql []byte) error {
	if s.Dialect() == types.DialectTypeMysql {
		// MySQL implicitly commits DDL. Never misrepresent this as rollback-safe.
		record.Dirty = true
		if err := s.RecordMigration(ctx, record); err != nil {
			return err
		}
		if err := s.ExecMigration(ctx, sql); err != nil {
			return err
		}
		return s.db.WithContext(ctx).Model(&gormMigrationRecord{}).Where("id = ?", record.ID).Update("dirty", false).Error
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		bound := *s
		bound.db = tx
		if err := bound.ExecMigration(ctx, sql); err != nil {
			return err
		}
		return bound.RecordMigration(ctx, record)
	})
}

func (s *GormStorage) RevertMigration(ctx context.Context, record types.MigrationRecord, sql []byte) error {
	if s.Dialect() == types.DialectTypeMysql {
		if err := s.db.WithContext(ctx).Model(&gormMigrationRecord{}).Where("id = ?", record.ID).Update("dirty", true).Error; err != nil {
			return err
		}
		if err := s.ExecMigration(ctx, sql); err != nil {
			return err
		}
		return s.RemoveMigrationRecord(ctx, record.ModuleName, record.Version)
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		bound := *s
		bound.db = tx
		if err := bound.ExecMigration(ctx, sql); err != nil {
			return err
		}
		return bound.RemoveMigrationRecord(ctx, record.ModuleName, record.Version)
	})
}
