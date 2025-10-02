package storage

import (
	"context"
	"database/sql"
)

// Storage defines the main storage interface
type Storage interface {
	// Initialize the storage backend
	Initialize(ctx context.Context) error

	// Close the storage connection
	Close() error

	// Migrate runs database migrations
	Migrate(ctx context.Context, models []interface{}) error

	// Transaction handling
	BeginTx(ctx context.Context) (Transaction, error)

	// Get the underlying connection
	DB() interface{}

	// Repository access
	UserRepository() UserRepository
	SessionRepository() SessionRepository

	// Generic repository for custom models
	Repository(model interface{}) Repository
}

// Transaction defines transaction operations
type Transaction interface {
	Commit() error
	Rollback() error

	// Repository access within transaction
	UserRepository() UserRepository
	SessionRepository() SessionRepository
	Repository(model interface{}) Repository
}

// Repository provides generic CRUD operations
type Repository interface {
	Create(ctx context.Context, entity interface{}) error
	FindByID(ctx context.Context, id interface{}, dest interface{}) error
	FindOne(ctx context.Context, query interface{}, dest interface{}) error
	FindAll(ctx context.Context, query interface{}, dest interface{}) error
	Update(ctx context.Context, entity interface{}) error
	Delete(ctx context.Context, entity interface{}) error
	Count(ctx context.Context, query interface{}) (int64, error)
}

// UserRepository defines user-specific operations
type UserRepository interface {
	Repository
	FindByEmail(ctx context.Context, email string, dest interface{}) error
	ExistsByEmail(ctx context.Context, email string) (bool, error)
}

// SessionRepository defines session-specific operations
type SessionRepository interface {
	Repository
	FindByToken(ctx context.Context, token string, dest interface{}) error
	DeleteExpired(ctx context.Context) error
	DeleteByUserID(ctx context.Context, userID string) error
}

// QueryOption represents query options for filtering, sorting, pagination
type QueryOption func(*QueryBuilder)

// QueryBuilder helps build database queries
type QueryBuilder struct {
	Conditions map[string]interface{}
	OrderBy    []string
	Limit      int
	Offset     int
	Preload    []string
}

// WithCondition adds a condition to the query
func WithCondition(field string, value interface{}) QueryOption {
	return func(qb *QueryBuilder) {
		if qb.Conditions == nil {
			qb.Conditions = make(map[string]interface{})
		}
		qb.Conditions[field] = value
	}
}

// WithOrderBy adds ordering to the query
func WithOrderBy(order string) QueryOption {
	return func(qb *QueryBuilder) {
		qb.OrderBy = append(qb.OrderBy, order)
	}
}

// WithLimit sets the query limit
func WithLimit(limit int) QueryOption {
	return func(qb *QueryBuilder) {
		qb.Limit = limit
	}
}

// WithOffset sets the query offset
func WithOffset(offset int) QueryOption {
	return func(qb *QueryBuilder) {
		qb.Offset = offset
	}
}

// WithPreload adds associations to preload
func WithPreload(associations ...string) QueryOption {
	return func(qb *QueryBuilder) {
		qb.Preload = append(qb.Preload, associations...)
	}
}

// NewQueryBuilder creates a new query builder
func NewQueryBuilder(opts ...QueryOption) *QueryBuilder {
	qb := &QueryBuilder{
		Conditions: make(map[string]interface{}),
	}
	for _, opt := range opts {
		opt(qb)
	}
	return qb
}

// Migrator handles database migrations
type Migrator interface {
	// AutoMigrate runs automatic migrations for models
	AutoMigrate(models ...interface{}) error

	// CreateTable creates a table for a model
	CreateTable(model interface{}) error

	// DropTable drops a table
	DropTable(model interface{}) error

	// HasTable checks if table exists
	HasTable(model interface{}) bool

	// AddColumn adds a column to a table
	AddColumn(model interface{}, column string) error

	// DropColumn drops a column from a table
	DropColumn(model interface{}, column string) error

	// GetSQLMigration generates SQL migration script
	GetSQLMigration(models ...interface{}) (string, error)
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	AutoMigrate     bool
	Driver          string // postgres, mysql, sqlite, mongodb
	DSN             string // Data Source Name
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime int
	LogLevel        string

	// For SQL databases
	DB *sql.DB

	// For custom implementations
	CustomStorage Storage
}
