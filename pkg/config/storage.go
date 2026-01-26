package config

import (
	"github.com/bete7512/goauth/pkg/types"
)

// Storage is an alias for types.Storage
// Use storage/gorm.NewStorage() or storage.NewGormStorage() to create instances
type Storage = types.Storage

// CoreStorage is an alias for types.CoreStorage
type CoreStorage = types.CoreStorage

// SessionStorage is an alias for types.SessionStorage
type SessionStorage = types.SessionStorage

// StatelessStorage is an alias for types.StatelessStorage
type StatelessStorage = types.StatelessStorage

// StorageConfig holds storage configuration
// Deprecated: Use storage/gorm.Config directly instead
type StorageConfig struct {
	// Driver specifies the storage backend: "gorm", "mongo", "sqlc", "custom"
	Driver types.DriverType

	// ORM/Database driver (for gorm: "postgres", "mysql", "sqlite")
	Dialect types.DialectType

	// DSN is the Data Source Name / connection string
	DSN string

	// Connection pool settings
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime int

	// AutoMigrate enables automatic database migration
	AutoMigrate bool

	// LogLevel for database operations
	LogLevel string
}
