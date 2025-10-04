package config

import (
	"context"
)

// Storage defines the main storage interface that all storage backends must implement
// This is storage-agnostic and doesn't know about any module-specific repositories
type Storage interface {
	// Initialize the storage backend
	Initialize(ctx context.Context) error

	// Close the storage connection
	Close() error

	// Migrate runs database migrations for the given models
	Migrate(ctx context.Context, models []interface{}) error

	// Transaction handling
	BeginTx(ctx context.Context) (Transaction, error)

	// Get the underlying connection (e.g., *gorm.DB, *mongo.Client)
	DB() interface{}

	// GetRepository retrieves a module's repository by name
	// Example: storage.GetRepository("core.user").(coreModels.UserRepository)
	GetRepository(name string) interface{}

	// RegisterRepository registers a module's repository
	// This is called internally by storage implementations
	RegisterRepository(name string, repo interface{})

	// Generic CRUD operations
	Create(ctx context.Context, model interface{}) error
	FindOne(ctx context.Context, dest interface{}, query interface{}, args ...interface{}) error
	FindAll(ctx context.Context, dest interface{}, query interface{}, args ...interface{}) error
	Update(ctx context.Context, model interface{}) error
	Delete(ctx context.Context, model interface{}) error
	DeleteWhere(ctx context.Context, model interface{}, query interface{}, args ...interface{}) error
}

// Transaction defines transaction operations
type Transaction interface {
	Commit() error
	Rollback() error

	// GetRepository retrieves a module's repository within transaction context
	GetRepository(name string) interface{}
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	// Driver specifies the storage backend: "gorm", "mongo", "sqlc", "custom"
	Driver string

	// ORM/Database driver (for gorm: "postgres", "mysql", "sqlite")
	Dialect string

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

// Helper functions for type-safe repository access

// GetTypedRepository safely casts repositories to their expected type
func GetTypedRepository[T any](storage Storage, name string) (T, error) {
	var zero T
	repo := storage.GetRepository(name)
	if repo == nil {
		return zero, ErrRepositoryNotFound(name)
	}

	typed, ok := repo.(T)
	if !ok {
		return zero, ErrRepositoryTypeMismatch(name)
	}

	return typed, nil
}

// GetTypedRepositoryFromTx is similar but for transactions
func GetTypedRepositoryFromTx[T any](tx Transaction, name string) (T, error) {
	var zero T
	repo := tx.GetRepository(name)
	if repo == nil {
		return zero, ErrRepositoryNotFound(name)
	}

	typed, ok := repo.(T)
	if !ok {
		return zero, ErrRepositoryTypeMismatch(name)
	}

	return typed, nil
}
