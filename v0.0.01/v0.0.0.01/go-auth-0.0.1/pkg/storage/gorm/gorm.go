package gorm

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/storage"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GormStorage implements the Storage interface using GORM
type GormStorage struct {
	db           *gorm.DB
	config       *storage.StorageConfig
	userRepo     storage.UserRepository
	sessionRepo  storage.SessionRepository
	genericRepos map[string]storage.Repository
}

// New creates a new GORM storage instance
func New(config *storage.StorageConfig) (storage.Storage, error) {
	if config == nil {
		return nil, fmt.Errorf("storage config is required")
	}

	return &GormStorage{
		config:       config,
		genericRepos: make(map[string]storage.Repository),
	}, nil
}

// Initialize initializes the GORM connection
func (s *GormStorage) Initialize(ctx context.Context) error {
	var dialector gorm.Dialector

	switch s.config.Driver {
	case "postgres":
		dialector = postgres.Open(s.config.DSN)
	case "mysql":
		dialector = mysql.Open(s.config.DSN)
	case "sqlite":
		dialector = sqlite.Open(s.config.DSN)
	default:
		return fmt.Errorf("unsupported database driver: %s", s.config.Driver)
	}

	// Configure GORM logger
	logLevel := logger.Silent
	switch s.config.LogLevel {
	case "error":
		logLevel = logger.Error
	case "warn":
		logLevel = logger.Warn
	case "info":
		logLevel = logger.Info
	}

	config := &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	}

	db, err := gorm.Open(dialector, config)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	s.db = db

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	if s.config.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(s.config.MaxOpenConns)
	}
	if s.config.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(s.config.MaxIdleConns)
	}
	if s.config.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(s.config.ConnMaxLifetime) * time.Second)
	}

	// Initialize repositories
	s.userRepo = NewUserRepository(s.db)
	s.sessionRepo = NewSessionRepository(s.db)

	return nil
}

// Close closes the database connection
func (s *GormStorage) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Migrate runs database migrations
func (s *GormStorage) Migrate(ctx context.Context, models []interface{}) error {
	if len(models) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).AutoMigrate(models...)
}

// BeginTx starts a new transaction
func (s *GormStorage) BeginTx(ctx context.Context) (storage.Transaction, error) {
	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}

	return &GormTransaction{
		tx:          tx,
		userRepo:    NewUserRepository(tx),
		sessionRepo: NewSessionRepository(tx),
	}, nil
}

// DB returns the underlying GORM database instance
func (s *GormStorage) DB() interface{} {
	return s.db
}

// UserRepository returns the user repository
func (s *GormStorage) UserRepository() storage.UserRepository {
	return s.userRepo
}

// SessionRepository returns the session repository
func (s *GormStorage) SessionRepository() storage.SessionRepository {
	return s.sessionRepo
}

// Repository returns a generic repository for a model
func (s *GormStorage) Repository(model interface{}) storage.Repository {
	modelType := fmt.Sprintf("%T", model)
	if repo, exists := s.genericRepos[modelType]; exists {
		return repo
	}

	repo := NewGenericRepository(s.db, model)
	s.genericRepos[modelType] = repo
	return repo
}

// GormTransaction implements the Transaction interface
type GormTransaction struct {
	tx          *gorm.DB
	userRepo    storage.UserRepository
	sessionRepo storage.SessionRepository
}

func (t *GormTransaction) Commit() error {
	return t.tx.Commit().Error
}

func (t *GormTransaction) Rollback() error {
	return t.tx.Rollback().Error
}

func (t *GormTransaction) UserRepository() storage.UserRepository {
	return t.userRepo
}

func (t *GormTransaction) SessionRepository() storage.SessionRepository {
	return t.sessionRepo
}

func (t *GormTransaction) Repository(model interface{}) storage.Repository {
	return NewGenericRepository(t.tx, model)
}
