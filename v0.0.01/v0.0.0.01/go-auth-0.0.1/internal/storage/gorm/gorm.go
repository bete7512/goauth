package gorm

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/internal/storage/gorm/modules/admin"
	"github.com/bete7512/goauth/internal/storage/gorm/modules/core"
	"github.com/bete7512/goauth/pkg/config"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GormStorage implements the Storage interface using GORM
type GormStorage struct {
	db           *gorm.DB
	repositories map[string]interface{}
}

var _ config.Storage = (*GormStorage)(nil)

// NewFromConfig creates a new GormStorage from configuration
func NewFromConfig(config config.StorageConfig) (config.Storage, error) {
	var dialector gorm.Dialector

	switch config.Dialect {
	case "postgres":
		dialector = postgres.Open(config.DSN)
	case "mysql":
		dialector = mysql.Open(config.DSN)
	case "sqlite":
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
	}
	if config.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	}
	if config.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(config.ConnMaxLifetime) * time.Second)
	}

	return NewGormStorage(db, config.CustomRepositories), nil
}

// NewGormStorage creates a new GormStorage instance
func NewGormStorage(db *gorm.DB, customRepos map[string]interface{}) *GormStorage {
	s := &GormStorage{
		db:           db,
		repositories: make(map[string]interface{}),
	}

	// Register all supported repositories
	s.registerRepositories(customRepos)

	return s
}

// registerRepositories registers all module repositories
func (s *GormStorage) registerRepositories(customRepos map[string]interface{}) {
	// Core module repositories
	s.repositories[config.CoreUserRepository] = core.NewUserRepository(s.db)
	s.repositories[config.CoreSessionRepository] = core.NewSessionRepository(s.db)

	// Admin module repositories
	s.repositories[config.AdminAuditLogRepository] = admin.NewAuditLogRepository(s.db)

	// TODO: Add other module repositories as they are implemented
	// s.repositories[storage.MagicLinkRepository] = magiclink.NewTokenRepository(s.db)
	// s.repositories[storage.TwoFactorRepository] = twofactor.NewSecretRepository(s.db)
	// s.repositories[storage.OAuthProviderRepository] = oauth.NewProviderRepository(s.db)
	// s.repositories[storage.OAuthTokenRepository] = oauth.NewTokenRepository(s.db)

	// Override with custom repositories if provided
	for name, repo := range customRepos {
		s.repositories[name] = repo
	}
}

func (s *GormStorage) Initialize(ctx context.Context) error {
	// Ping the database to ensure connection is valid
	sqlDB, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}
	return sqlDB.PingContext(ctx)
}

func (s *GormStorage) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *GormStorage) Migrate(ctx context.Context, models []interface{}) error {
	return s.db.WithContext(ctx).AutoMigrate(models...)
}

func (s *GormStorage) BeginTx(ctx context.Context) (config.Transaction, error) {
	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}

	return &GormTransaction{
		tx:           tx,
		repositories: s.createTransactionRepositories(tx),
	}, nil
}

func (s *GormStorage) DB() interface{} {
	return s.db
}

func (s *GormStorage) GetRepository(name string) interface{} {
	return s.repositories[name]
}

func (s *GormStorage) RegisterRepository(name string, repo interface{}) {
	s.repositories[name] = repo
}

// createTransactionRepositories creates repository instances with transaction context
func (s *GormStorage) createTransactionRepositories(tx *gorm.DB) map[string]interface{} {
	repos := make(map[string]interface{})

	// Core module repositories
	repos[config.CoreUserRepository] = core.NewUserRepository(tx)
	repos[config.CoreSessionRepository] = core.NewSessionRepository(tx)

	// Admin module repositories
	repos[config.AdminAuditLogRepository] = admin.NewAuditLogRepository(tx)

	// TODO: Add other module repositories

	return repos
}

// GormTransaction implements the Transaction interface
type GormTransaction struct {
	tx           *gorm.DB
	repositories map[string]interface{}
}

var _ config.Transaction = (*GormTransaction)(nil)

func (t *GormTransaction) Commit() error {
	return t.tx.Commit().Error
}

func (t *GormTransaction) Rollback() error {
	return t.tx.Rollback().Error
}

func (t *GormTransaction) GetRepository(name string) interface{} {
	return t.repositories[name]
}
