package gorm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage/gorm/auditlog"
	"github.com/bete7512/goauth/storage/gorm/core"
	"github.com/bete7512/goauth/storage/gorm/oauth"
	"github.com/bete7512/goauth/storage/gorm/session"
	"github.com/bete7512/goauth/storage/gorm/twofactor"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Compile-time checks
var _ types.Storage = (*GormStorage)(nil)
var _ types.MigrationApplier = (*GormStorage)(nil)

// Config holds GORM storage configuration
type Config struct {
	// Dialect specifies the database type
	Dialect types.DialectType

	// DSN is the data source name / connection string
	DSN string

	// Connection pool settings
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration

	// LogLevel for database operations ("silent", "error", "warn", "info")
	LogLevel string
}

// GormStorage implements types.Storage using GORM
// This is the main entry point for GORM-based storage
//
// Usage:
//
//	store, _ := gorm.NewStorage(gorm.Config{...})
//	auth.New(&config.Config{Storage: store})
type GormStorage struct {
	db               *gorm.DB
	dialect          types.DialectType
	coreStorage      *core.GormCoreStorage
	sessionStorage   *session.GormSessionStorage
	auditLogStoarage *auditlog.GormAuditLogStorage
	oauthStorage     *oauth.GormOAuthStorage
	twoFactorStorage *twofactor.TwoFactorStorage
}

// NewStorage creates a new GORM storage from configuration
func NewStorage(config Config) (*GormStorage, error) {
	var dialector gorm.Dialector

	switch config.Dialect {
	case types.DialectTypePostgres:
		dialector = postgres.Open(config.DSN)
	case types.DialectTypeMysql:
		dialector = mysql.Open(config.DSN)
	case types.DialectTypeSqlite:
		dialector = sqlite.Open(config.DSN)
	default:
		return nil, fmt.Errorf("unsupported dialect: %s", config.Dialect)
	}

	// Configure logger
	logLevel := logger.Silent
	switch config.LogLevel {
	case "info":
		logLevel = logger.Info
	case "warn":
		logLevel = logger.Warn
	case "error":
		logLevel = logger.Error
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	if config.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	} else {
		sqlDB.SetMaxOpenConns(25)
	}
	if config.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	} else {
		sqlDB.SetMaxIdleConns(5)
	}
	if config.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(config.ConnMaxLifetime)
	} else {
		sqlDB.SetConnMaxLifetime(5 * time.Minute)
	}

	storage := NewStorageFromDB(db)
	storage.dialect = config.Dialect
	return storage, nil
}

// NewStorageFromDB creates a new GORM storage from an existing *gorm.DB
// Use this if you already have a database connection
func NewStorageFromDB(db *gorm.DB) *GormStorage {
	return &GormStorage{
		db:               db,
		coreStorage:      core.NewCoreStorage(db),
		sessionStorage:   session.NewSessionStorage(db),
		auditLogStoarage: auditlog.NewAuditLogStorage(db),
		oauthStorage:     oauth.NewOAuthStorage(db),
		twoFactorStorage: twofactor.NewTwoFactorStorage(db),
	}
}

// Core returns storage for the core module
func (s *GormStorage) Core() types.CoreStorage {
	return s.coreStorage
}

// Session returns storage for the session module
func (s *GormStorage) Session() types.SessionStorage {
	return s.sessionStorage
}

// Stateless returns storage for the stateless module
// Returns nil because stateless uses token version approach (no extra storage needed)
func (s *GormStorage) Stateless() types.StatelessStorage {
	return nil
}

// Audit Log returns storage for the Auditlog module
func (s *GormStorage) AuditLog() types.AuditLogStorage {
	return s.auditLogStoarage
}

// Admin returns storage for the admin module
func (s *GormStorage) Admin() types.AdminStorage {
	return nil
}

// OAuth returns storage for the OAuth module
func (s *GormStorage) OAuth() types.OAuthStorage {
	return s.oauthStorage
}

// TwoFactorAuth returns storage for the two-factor authentication module
func (s *GormStorage) TwoFactorAuth() types.TwoFactorStorage {
	return s.twoFactorStorage
}

// Close closes the database connection
func (s *GormStorage) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// DB returns the underlying *gorm.DB connection
func (s *GormStorage) DB() any {
	return s.db
}

// ─── MigrationApplier implementation ────────────────────────────────────────

// Dialect returns the DB dialect set during construction.
// Falls back to GORM's dialector name when constructed via NewStorageFromDB (no dialect stored).
func (s *GormStorage) Dialect() types.DialectType {
	if s.dialect != "" {
		return s.dialect
	}
	return types.DialectType(s.db.Dialector.Name())
}

// EnsureMigrationsTable creates the goauth_migrations tracking table if it does not exist.
func (s *GormStorage) EnsureMigrationsTable(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(&gormMigrationRecord{})
}

// AppliedMigrations returns all rows from the goauth_migrations table.
func (s *GormStorage) AppliedMigrations(ctx context.Context) ([]types.MigrationRecord, error) {
	var rows []gormMigrationRecord
	if err := s.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, err
	}
	records := make([]types.MigrationRecord, len(rows))
	for i, r := range rows {
		records[i] = types.MigrationRecord{
			ID:         r.ID,
			ModuleName: r.ModuleName,
			Dialect:    r.Dialect,
			AppliedAt:  r.AppliedAt,
			Status:     r.Status,
		}
	}
	return records, nil
}

// ExecMigration executes a raw SQL script by splitting on ";" and running each statement.
// Sufficient for DDL-only migration files (no semicolons inside string literals or comments).
func (s *GormStorage) ExecMigration(ctx context.Context, sql []byte) error {
	for _, stmt := range splitSQLStatements(string(sql)) {
		if err := s.db.WithContext(ctx).Exec(stmt).Error; err != nil {
			return fmt.Errorf("migration statement failed: %w\nSQL: %s", err, stmt)
		}
	}
	return nil
}

// RecordMigration inserts a migration record into goauth_migrations.
func (s *GormStorage) RecordMigration(ctx context.Context, record types.MigrationRecord) error {
	row := gormMigrationRecord{
		ID:         record.ID,
		ModuleName: record.ModuleName,
		Dialect:    record.Dialect,
		AppliedAt:  record.AppliedAt,
		Status:     record.Status,
	}
	return s.db.WithContext(ctx).Create(&row).Error
}

// RemoveMigrationRecord deletes a migration record by module name (used on rollback).
func (s *GormStorage) RemoveMigrationRecord(ctx context.Context, moduleName string) error {
	return s.db.WithContext(ctx).
		Where("module_name = ?", moduleName).
		Delete(&gormMigrationRecord{}).Error
}

// splitSQLStatements splits a SQL script on ";" and returns non-empty trimmed statements.
func splitSQLStatements(script string) []string {
	parts := strings.Split(script, ";")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			result = append(result, s)
		}
	}
	return result
}
