package types

//go:generate mockgen -destination=../../internal/mocks/mock_storage.go -package=mocks github.com/bete7512/goauth/pkg/types Storage,CoreStorage,SessionStorage,StatelessStorage,AdminStorage,OAuthStorage,TwoFactorStorage

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
)

// DialectType represents database dialect for SQL databases
type DialectType string

const (
	DialectTypePostgres DialectType = "postgres"
	DialectTypeMysql    DialectType = "mysql"
	DialectTypeSqlite   DialectType = "sqlite"
)

// DriverType represents storage backend type
type DriverType string

const (
	DriverTypeGorm  DriverType = "gorm"
	DriverTypeMongo DriverType = "mongo"
	DriverTypeSqlc  DriverType = "sqlc"
)

type Storage interface {
	// Core returns storage for the core module (users, tokens, etc.)
	Core() CoreStorage

	// Session returns storage for the session module
	// Returns nil if session storage is not needed/available
	Session() SessionStorage

	// Stateless returns storage for the stateless module
	// Returns nil if using token version approach (no extra storage needed)
	Stateless() StatelessStorage

	// Admin returns storage for the admin module
	// Returns nil if admin storage is not needed/available
	Admin() AdminStorage

	// OAuth returns storage for the OAuth module
	// Returns nil if OAuth storage is not needed/available
	OAuth() OAuthStorage

	// TwoFactorAuth returns storage for the two-factor authentication module
	// Returns nil if 2FA storage is not needed/available
	TwoFactorAuth() TwoFactorStorage

	// Audit Log
	AuditLog() AuditLogStorage

	// Close closes all storage connections
	Close() error

	// DB returns the underlying database connection (for advanced use)
	DB() interface{}
}

// CoreStorage defines storage interface for the core module
type CoreStorage interface {
	Users() models.UserRepository
	Tokens() models.TokenRepository
	ExtendedAttributes() models.ExtendedAttributeRepository
	WithTransaction(ctx context.Context, fn func(tx CoreStorage) error) error
}

// SessionStorage defines storage interface for the session module
type SessionStorage interface {
	Sessions() models.SessionRepository
	WithTransaction(ctx context.Context, fn func(tx SessionStorage) error) error
}

// StatelessStorage defines storage interface for the stateless module (optional)
type StatelessStorage interface {
	Blacklist() models.BlacklistRepository
}

// AdminStorage defines storage interface for the admin module
type AdminStorage interface {
}


type AuditLogStorage interface {
	AuditLogs() models.AuditLogRepository
	WithTransaction(ctx context.Context, fn func(tx AuditLogStorage) error) error
}

// OAuthStorage defines storage interface for the OAuth module
type OAuthStorage interface {
	Accounts() models.AccountRepository
	WithTransaction(ctx context.Context, fn func(tx OAuthStorage) error) error
}

// TwoFactorStorage defines storage interface for the two-factor authentication module
type TwoFactorStorage interface {
	TwoFactor() models.TwoFactorRepository
	BackupCodes() models.BackupCodeRepository
	WithTransaction(ctx context.Context, fn func(tx TwoFactorStorage) error) error
}
