package gorm

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/types"
	"github.com/bete7512/goauth/storage/gorm/auditlog"
	"github.com/bete7512/goauth/storage/gorm/core"
	"github.com/bete7512/goauth/storage/gorm/session"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Compile-time check: GormStorage implements types.Storage
var _ types.Storage = (*GormStorage)(nil)

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
	coreStorage      *core.GormCoreStorage
	sessionStorage   *session.GormSessionStorage
	auditLogStoarage *auditlog.GormAuditLogStorage
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

	return NewStorageFromDB(db), nil
}

// NewStorageFromDB creates a new GORM storage from an existing *gorm.DB
// Use this if you already have a database connection
func NewStorageFromDB(db *gorm.DB) *GormStorage {
	return &GormStorage{
		db:               db,
		coreStorage:      core.NewCoreStorage(db),
		sessionStorage:   session.NewSessionStorage(db),
		auditLogStoarage: auditlog.NewAuditLogStorage(db),
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

// Migrate runs database migrations for the provided models
// Models are collected from registered modules via their Models() method
func (s *GormStorage) Migrate(ctx context.Context, models []interface{}) error {
	if len(models) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).AutoMigrate(models...)
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
