package config

import (
	"context"
)

// Repository name constants for type-safe access
const (
	// Core module repositories
	CoreUserRepository    = "core.user"
	CoreSessionRepository = "core.session"

	// Admin module repositories
	AdminAuditLogRepository = "admin.auditlog"

	// MagicLink module repositories
	MagicLinkRepository = "magiclink.token"

	// TwoFactor module repositories
	TwoFactorRepository = "twofactor.secret"

	// OAuth module repositories
	OAuthProviderRepository = "oauth.provider"
	OAuthTokenRepository    = "oauth.token"
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

	// CustomStorage allows users to provide their own storage implementation
	CustomStorage Storage

	// CustomRepositories allows users to provide custom repository implementations
	// Key format: "module.repository" (e.g., "core.user", "admin.auditlog")
	CustomRepositories map[string]interface{}
}

// RepositoryFactory creates repository instances for a given storage backend
// Each storage implementation (gorm, mongo, etc.) should implement this
type RepositoryFactory interface {
	// CreateRepositories creates all supported repository instances
	// Returns a map of repository name to repository instance
	// Example: {"core.user": userRepo, "core.session": sessionRepo}
	CreateRepositories(db interface{}) map[string]interface{}

	// CreateTransactionRepositories creates repository instances for transaction context
	CreateTransactionRepositories(tx interface{}) map[string]interface{}
}
