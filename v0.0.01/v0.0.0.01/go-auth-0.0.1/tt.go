// ============================================================================
// PROJECT STRUCTURE
// ============================================================================
// go-auth/
// ├── auth.go                    # This file - Main library
// ├── config.go
// ├── module.go
// ├── helpers.go
// ├── errors.go
// │
// ├── storage/
// │   ├── storage.go
// │   └── gorm/
// │       └── gorm.go
// │
// ├── core/
// │   ├── module.go
// │   ├── models/
// │   │   ├── user.go
// │   │   ├── session.go
// │   │   └── token.go
// │   ├── repository/
// │   │   ├── user_repository.go
// │   │   └── session_repository.go
// │   ├── service/
// │   │   ├── auth_service.go
// │   │   └── session_service.go
// │   ├── handlers/
// │   │   ├── handlers.go
// │   │   ├── signup.go
// │   │   ├── login.go
// │   │   ├── logout.go
// │   │   ├── profile.go
// │   │   └── me.go
// │   └── middleware.go
// │
// └── modules/
//     ├── twofactor/
//     │   ├── module.go
//     │   ├── models/
//     │   │   └── twofactor.go
//     │   ├── repository/
//     │   │   └── twofactor_repository.go
//     │   ├── service/
//     │   │   └── totp_service.go
//     │   ├── handlers/
//     │   │   ├── handlers.go
//     │   │   ├── setup.go
//     │   │   ├── verify.go
//     │   │   └── disable.go
//     │   └── middleware.go
//     │
//     ├── csrf/
//     │   ├── module.go
//     │   ├── service/
//     │   │   └── token_service.go
//     │   └── middleware.go
//     │
//     ├── passkey/
//     │   ├── module.go
//     │   ├── models/
//     │   ├── repository/
//     │   ├── service/
//     │   └── handlers/
//     │
//     └── admin/
//         ├── module.go
//         ├── models/
//         ├── repository/
//         ├── service/
//         ├── handlers/
//         └── middleware.go

// ============================================================================
// FILE: auth.go - Main Library Entry Point
// ============================================================================
package auth

import (
	"context"
	"net/http"

	"github.com/yourusername/go-auth/storage"
)



// ============================================================================
// FILE: config.go
// ============================================================================
package auth

import (
	"time"

	"github.com/yourusername/go-auth/storage"
)

// Config holds library configuration

// ============================================================================
// FILE: module.go
// ============================================================================
package auth

import (
	"context"
	"net/http"
)

// Module represents a pluggable authentication module
type Module interface {
	// Name returns the module identifier
	Name() string

	// Init initializes the module with dependencies
	Init(ctx context.Context, deps ModuleDependencies) error

	// Handler returns the HTTP handler and mount path
	Handler() (http.Handler, string)

	// Middlewares returns HTTP middlewares
	Middlewares() []func(http.Handler) http.Handler

	// Models returns database models for migration
	Models() []interface{}

	// Hooks returns lifecycle hooks
	Hooks() Hooks

	// Dependencies returns required module names
	Dependencies() []string
}

// ModuleDependencies provides access to shared services
type ModuleDependencies struct {
	Storage storage.Storage
	Config  *Config
	Events  EventBus
}

// Hooks allow modules to extend behavior
type Hooks struct {
	BeforeSignup []HookFunc
	AfterSignup  []HookFunc
	BeforeLogin  []HookFunc
	AfterLogin   []HookFunc
	BeforeLogout []HookFunc
	AfterLogout  []HookFunc
}

// HookFunc represents a lifecycle hook
type HookFunc func(ctx context.Context, data *HookData) error

// HookData contains event data
type HookData struct {
	User    interface{}
	Session interface{}
	Request *http.Request
	Data    map[string]interface{}
}

// EventBus for pub/sub pattern
type EventBus interface {
	Publish(event string, data interface{})
	Subscribe(event string, handler EventHandler)
}

// EventHandler handles events
type EventHandler func(ctx context.Context, data interface{}) error

// ============================================================================
// FILE: helpers.go
// ============================================================================
package auth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/yourusername/go-auth/core/models"
)

// GetUser extracts authenticated user from context
func GetUser(ctx context.Context) (*models.User, bool)

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) (string, bool)

// JSON writes JSON response
func JSON(w http.ResponseWriter, status int, data interface{}) error

// Error writes error response
func Error(w http.ResponseWriter, status int, message string) error

// ParseBody parses request body into struct
func ParseBody(r *http.Request, v interface{}) error

// ============================================================================
// FILE: errors.go
// ============================================================================
package auth

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidToken       = errors.New("invalid token")
	ErrSessionExpired     = errors.New("session expired")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrModuleNotFound     = errors.New("module not found")
	ErrInvalidConfig      = errors.New("invalid configuration")
)

// ============================================================================
// FILE: storage/storage.go
// ============================================================================
package storage

import "context"

// Storage interface for database operations
type Storage interface {
	// DB returns the underlying database connection
	DB() interface{}

	// AutoMigrate runs automatic migrations
	AutoMigrate(models ...interface{}) error

	// Transaction executes function within a transaction
	Transaction(ctx context.Context, fn func(tx Storage) error) error

	// Query returns a query builder (optional)
	Query() QueryBuilder
}

// QueryBuilder provides fluent query interface
type QueryBuilder interface {
	Table(name string) QueryBuilder
	Where(column string, value interface{}) QueryBuilder
	First(dest interface{}) error
	Find(dest interface{}) error
	Create(value interface{}) error
	Update(value interface{}) error
	Delete(value interface{}) error
}

// ============================================================================
// FILE: storage/gorm/gorm.go
// ============================================================================
package gorm

import (
	"context"

	"github.com/yourusername/go-auth/storage"
	"gorm.io/gorm"
)

// GormStorage implements storage.Storage using GORM
type GormStorage struct {
	db *gorm.DB
}

// NewStorage creates a new GORM storage instance
func NewStorage(db *gorm.DB) storage.Storage

func (s *GormStorage) DB() interface{}

func (s *GormStorage) AutoMigrate(models ...interface{}) error

func (s *GormStorage) Transaction(ctx context.Context, fn func(tx storage.Storage) error) error

func (s *GormStorage) Query() storage.QueryBuilder

// GormQueryBuilder implements storage.QueryBuilder
type GormQueryBuilder struct {
	db *gorm.DB
}

func (q *GormQueryBuilder) Table(name string) storage.QueryBuilder

func (q *GormQueryBuilder) Where(column string, value interface{}) storage.QueryBuilder

func (q *GormQueryBuilder) First(dest interface{}) error

func (q *GormQueryBuilder) Find(dest interface{}) error

func (q *GormQueryBuilder) Create(value interface{}) error

func (q *GormQueryBuilder) Update(value interface{}) error

func (q *GormQueryBuilder) Delete(value interface{}) error

// ============================================================================
// FILE: core/module.go
// ============================================================================
package core

import (
	"context"
	"net/http"

	"github.com/yourusername/go-auth"
	"github.com/yourusername/go-auth/core/handlers"
	"github.com/yourusername/go-auth/core/repository"
	"github.com/yourusername/go-auth/core/service"
)

// Module represents the core authentication module
type Module struct {
	config      *Config
	userRepo    *repository.UserRepository
	sessionRepo *repository.SessionRepository
	authService *service.AuthService
	handlers    *handlers.Handlers
}

// Config for core module
type Config struct {
	PasswordMinLength int
	RequireEmail      bool
	AllowSignup       bool
}

// New creates a new core module
func New() *Module

func (m *Module) Name() string

func (m *Module) Init(ctx context.Context, deps auth.ModuleDependencies) error

func (m *Module) Handler() (http.Handler, string)

func (m *Module) Middlewares() []func(http.Handler) http.Handler

func (m *Module) Models() []interface{}

func (m *Module) Hooks() auth.Hooks

func (m *Module) Dependencies() []string

// AuthMiddleware returns the authentication middleware
func (m *Module) AuthMiddleware() func(http.Handler) http.Handler

// ============================================================================
// FILE: core/models/user.go
// ============================================================================
package models

import "time"

// User represents an authenticated user
type User struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	Email     string    `json:"email" gorm:"uniqueIndex;not null"`
	Password  string    `json:"-" gorm:"not null"`
	Name      string    `json:"name"`
	Avatar    string    `json:"avatar"`
	Active    bool      `json:"active" gorm:"default:true"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName specifies the table name
func (User) TableName() string

// ============================================================================
// FILE: core/models/session.go
// ============================================================================
package models

import "time"

// Session represents a user session
type Session struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserID    string    `json:"user_id" gorm:"not null;index"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null;index"`
	UserAgent string    `json:"user_agent"`
	IPAddress string    `json:"ip_address"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

func (Session) TableName() string

// IsExpired checks if session is expired
func (s *Session) IsExpired() bool

// ============================================================================
// FILE: core/models/token.go
// ============================================================================
package models

import "time"

// Token represents various types of tokens (reset, verify, etc.)
type Token struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	UserID    string    `json:"user_id" gorm:"not null;index"`
	Type      string    `json:"type" gorm:"not null;index"`
	Token     string    `json:"token" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null;index"`
	Used      bool      `json:"used" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`

	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

func (Token) TableName() string

func (t *Token) IsExpired() bool

// ============================================================================
// FILE: core/repository/user_repository.go
// ============================================================================
package repository

import (
	"context"

	"github.com/yourusername/go-auth/core/models"
	"github.com/yourusername/go-auth/storage"
)

// UserRepository handles user database operations
type UserRepository struct {
	storage storage.Storage
}

// NewUserRepository creates a new user repository
func NewUserRepository(storage storage.Storage) *UserRepository

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *models.User) error

// FindByID finds a user by ID
func (r *UserRepository) FindByID(ctx context.Context, id string) (*models.User, error)

// FindByEmail finds a user by email
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error)

// Update updates a user
func (r *UserRepository) Update(ctx context.Context, user *models.User) error

// Delete soft deletes a user
func (r *UserRepository) Delete(ctx context.Context, id string) error

// List lists users with pagination
func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]*models.User, error)

// ============================================================================
// FILE: core/repository/session_repository.go
// ============================================================================
package repository

import (
	"context"

	"github.com/yourusername/go-auth/core/models"
	"github.com/yourusername/go-auth/storage"
)

// SessionRepository handles session database operations
type SessionRepository struct {
	storage storage.Storage
}

func NewSessionRepository(storage storage.Storage) *SessionRepository

func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error

func (r *SessionRepository) FindByToken(ctx context.Context, token string) (*models.Session, error)

func (r *SessionRepository) FindByUserID(ctx context.Context, userID string) ([]*models.Session, error)

func (r *SessionRepository) Delete(ctx context.Context, token string) error

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID string) error

func (r *SessionRepository) DeleteExpired(ctx context.Context) error

// ============================================================================
// FILE: core/service/auth_service.go
// ============================================================================
package service

import (
	"context"

	"github.com/yourusername/go-auth/core/models"
	"github.com/yourusername/go-auth/core/repository"
)

// AuthService handles authentication business logic
type AuthService struct {
	userRepo    *repository.UserRepository
	sessionRepo *repository.SessionRepository
	config      *Config
}

type Config struct {
	SecretKey       string
	SessionDuration int
	PasswordMinLen  int
}

func NewAuthService(userRepo *repository.UserRepository, sessionRepo *repository.SessionRepository, config *Config) *AuthService

// Signup creates a new user account
func (s *AuthService) Signup(ctx context.Context, email, password, name string) (*models.User, error)

// Login authenticates a user and creates a session
func (s *AuthService) Login(ctx context.Context, email, password string) (*models.User, *models.Session, error)

// Logout invalidates a session
func (s *AuthService) Logout(ctx context.Context, token string) error

// ValidateSession validates a session token
func (s *AuthService) ValidateSession(ctx context.Context, token string) (*models.User, error)

// HashPassword hashes a password
func (s *AuthService) HashPassword(password string) (string, error)

// VerifyPassword verifies a password against a hash
func (s *AuthService) VerifyPassword(hashedPassword, password string) bool

// ============================================================================
// FILE: core/service/session_service.go
// ============================================================================
package service

import (
	"context"

	"github.com/yourusername/go-auth/core/models"
	"github.com/yourusername/go-auth/core/repository"
)

// SessionService handles session management
type SessionService struct {
	sessionRepo *repository.SessionRepository
	config      *SessionConfig
}

type SessionConfig struct {
	Duration int
}

func NewSessionService(sessionRepo *repository.SessionRepository, config *SessionConfig) *SessionService

func (s *SessionService) CreateSession(ctx context.Context, userID string, userAgent, ipAddress string) (*models.Session, error)

func (s *SessionService) GetSession(ctx context.Context, token string) (*models.Session, error)

func (s *SessionService) RevokeSession(ctx context.Context, token string) error

func (s *SessionService) RevokeAllUserSessions(ctx context.Context, userID string) error

func (s *SessionService) CleanupExpiredSessions(ctx context.Context) error

func (s *SessionService) GenerateToken() (string, error)

// ============================================================================
// FILE: core/handlers/handlers.go
// ============================================================================
package handlers

import (
	"github.com/yourusername/go-auth/core/service"
)

// Handlers contains all HTTP handlers for core module
type Handlers struct {
	authService *service.AuthService
}

// NewHandlers creates a new handlers instance
func NewHandlers(authService *service.AuthService) *Handlers

// ============================================================================
// FILE: core/handlers/signup.go
// ============================================================================
package handlers

import "net/http"

// SignupRequest represents signup request body
type SignupRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Name     string `json:"name"`
}

// SignupResponse represents signup response
type SignupResponse struct {
	User  interface{} `json:"user"`
	Token string      `json:"token"`
}

// Signup handles user signup
func (h *Handlers) Signup(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: core/handlers/login.go
// ============================================================================
package handlers

import "net/http"

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	User  interface{} `json:"user"`
	Token string      `json:"token"`
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: core/handlers/logout.go
// ============================================================================
package handlers

import "net/http"

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: core/handlers/profile.go
// ============================================================================
package handlers

import "net/http"

type UpdateProfileRequest struct {
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
}

func (h *Handlers) UpdateProfile(w http.ResponseWriter, r *http.Request)

func (h *Handlers) DeactivateAccount(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: core/handlers/me.go
// ============================================================================
package handlers

import "net/http"

func (h *Handlers) Me(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: core/middleware.go
// ============================================================================
package core

import (
	"context"
	"net/http"
)

// contextKey is a custom type for context keys
type contextKey string

const (
	UserContextKey contextKey = "user"
)

// authMiddleware validates the session token and adds user to context
func (m *Module) authMiddleware(next http.Handler) http.Handler

// OptionalAuthMiddleware is like authMiddleware but doesn't fail if no token
func (m *Module) OptionalAuthMiddleware() func(http.Handler) http.Handler

// ============================================================================
// FILE: modules/twofactor/module.go
// ============================================================================
package twofactor

import (
	"context"
	"net/http"

	"github.com/yourusername/go-auth"
	"github.com/yourusername/go-auth/modules/twofactor/handlers"
	"github.com/yourusername/go-auth/modules/twofactor/repository"
	"github.com/yourusername/go-auth/modules/twofactor/service"
)

// Module represents the two-factor authentication module
type Module struct {
	config  *Config
	repo    *repository.TwoFactorRepository
	service *service.TOTPService
	handler *handlers.Handlers
}

type Config struct {
	Issuer     string
	CodeLength int
}

func New() *Module

func (m *Module) Name() string

func (m *Module) Init(ctx context.Context, deps auth.ModuleDependencies) error

func (m *Module) Handler() (http.Handler, string)

func (m *Module) Middlewares() []func(http.Handler) http.Handler

func (m *Module) Models() []interface{}

func (m *Module) Hooks() auth.Hooks

func (m *Module) Dependencies() []string

// Require2FAMiddleware ensures user has 2FA enabled and verified
func (m *Module) Require2FAMiddleware() func(http.Handler) http.Handler

// ============================================================================
// FILE: modules/twofactor/models/twofactor.go
// ============================================================================
package models

import "time"

type TwoFactor struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	UserID       string    `json:"user_id" gorm:"not null;uniqueIndex"`
	Secret       string    `json:"-" gorm:"not null"`
	Enabled      bool      `json:"enabled" gorm:"default:false"`
	BackupCodes  string    `json:"-" gorm:"type:text"`
	VerifiedAt   *time.Time `json:"verified_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (TwoFactor) TableName() string

// ============================================================================
// FILE: modules/twofactor/repository/twofactor_repository.go
// ============================================================================
package repository

import (
	"context"

	"github.com/yourusername/go-auth/modules/twofactor/models"
	"github.com/yourusername/go-auth/storage"
)

type TwoFactorRepository struct {
	storage storage.Storage
}

func NewTwoFactorRepository(storage storage.Storage) *TwoFactorRepository

func (r *TwoFactorRepository) Create(ctx context.Context, tf *models.TwoFactor) error

func (r *TwoFactorRepository) FindByUserID(ctx context.Context, userID string) (*models.TwoFactor, error)

func (r *TwoFactorRepository) Update(ctx context.Context, tf *models.TwoFactor) error

func (r *TwoFactorRepository) Delete(ctx context.Context, userID string) error

// ============================================================================
// FILE: modules/twofactor/service/totp_service.go
// ============================================================================
package service

import (
	"context"

	"github.com/yourusername/go-auth/modules/twofactor/models"
	"github.com/yourusername/go-auth/modules/twofactor/repository"
)

type TOTPService struct {
	repo   *repository.TwoFactorRepository
	config *Config
}

type Config struct {
	Issuer string
}

func NewTOTPService(repo *repository.TwoFactorRepository, config *Config) *TOTPService

func (s *TOTPService) GenerateSecret(ctx context.Context, userID, email string) (*models.TwoFactor, string, error)

func (s *TOTPService) VerifyCode(ctx context.Context, userID, code string) (bool, error)

func (s *TOTPService) Enable(ctx context.Context, userID, code string) error

func (s *TOTPService) Disable(ctx context.Context, userID string) error

func (s *TOTPService) GenerateBackupCodes(ctx context.Context, userID string) ([]string, error)

func (s *TOTPService) VerifyBackupCode(ctx context.Context, userID, code string) (bool, error)

// ============================================================================
// FILE: modules/twofactor/handlers/handlers.go
// ============================================================================
package handlers

import (
	"github.com/yourusername/go-auth/modules/twofactor/service"
)

type Handlers struct {
	totpService *service.TOTPService
}

func NewHandlers(totpService *service.TOTPService) *Handlers

// ============================================================================
// FILE: modules/twofactor/handlers/setup.go
// ============================================================================
package handlers

import "net/http"

type SetupResponse struct {
	Secret string `json:"secret"`
	QRCode string `json:"qr_code"`
}

func (h *Handlers) Setup(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: modules/twofactor/handlers/verify.go
// ============================================================================
package handlers

import "net/http"

type VerifyRequest struct {
	Code string `json:"code" validate:"required"`
}

func (h *Handlers) Verify(w http.ResponseWriter, r *http.Request)

func (h *Handlers) Enable(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: modules/twofactor/handlers/disable.go
// ============================================================================
package handlers

import "net/http"

func (h *Handlers) Disable(w http.ResponseWriter, r *http.Request)

func (h *Handlers) GenerateBackupCodes(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: modules/twofactor/middleware.go
// ============================================================================
package twofactor

import "net/http"

func (m *Module) require2FAMiddleware(next http.Handler) http.Handler

// ============================================================================
// FILE: modules/csrf/module.go
// ============================================================================
package csrf

import (
	"context"
	"net/http"

	"github.com/yourusername/go-auth"
	"github.com/yourusername/go-auth/modules/csrf/service"
)

type Module struct {
	config  *Config
	service *service.TokenService
}

type Config struct {
	TokenLength int
	CookieName  string
	HeaderName  string
}

func New() *Module

func (m *Module) Name() string

func (m *Module) Init(ctx context.Context, deps auth.ModuleDependencies) error

func (m *Module) Handler() (http.Handler, string)

func (m *Module) Middlewares() []func(http.Handler) http.Handler

func (m *Module) Models() []interface{}

func (m *Module) Hooks() auth.Hooks

func (m *Module) Dependencies() []string

// ============================================================================
// FILE: modules/csrf/service/token_service.go
// ============================================================================
package service

import "context"

type TokenService struct {
	config *Config
}

type Config struct {
	TokenLength int
	Secret      string
}

func NewTokenService(config *Config) *TokenService

func (s *TokenService) GenerateToken(ctx context.Context) (string, error)

func (s *TokenService) ValidateToken(ctx context.Context, token string) (bool, error)

// ============================================================================
// FILE: modules/csrf/middleware.go
// ============================================================================
package csrf

import "net/http"

func (m *Module) csrfMiddleware(next http.Handler) http.Handler

// ============================================================================
// FILE: modules/admin/module.go
// ============================================================================
package admin

import (
	"context"
	"net/http"

	"github.com/yourusername/go-auth"
	"github.com/yourusername/go-auth/modules/admin/handlers"
	"github.com/yourusername/go-auth/modules/admin/repository"
	"github.com/yourusername/go-auth/modules/admin/service"
)

type Module struct {
	config      *Config
	auditRepo   *repository.AuditLogRepository
	adminService *service.AdminService
	handlers    *handlers.Handlers
}

type Config struct {
	AdminRoles []string
}

func New() *Module

func (m *Module) Name() string

func (m *Module) Init(ctx context.Context, deps auth.ModuleDependencies) error

func (m *Module) Handler() (http.Handler, string)

func (m *Module) Middlewares() []func(http.Handler) http.Handler

func (m *Module) Models() []interface{}

func (m *Module) Hooks() auth.Hooks

func (m *Module) Dependencies() []string

func (m *Module) RequireAdminMiddleware() func(http.Handler) http.Handler

// ============================================================================
// FILE: modules/admin/models/audit_log.go
// ============================================================================
package models

import "time"

type AuditLog struct {
	ID        string                 `json:"id" gorm:"primaryKey"`
	UserID    string                 `json:"user_id" gorm:"index"`
	Action    string                 `json:"action" gorm:"not null;index"`
	Resource  string                 `json:"resource"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Metadata  map[string]interface{} `json:"metadata" gorm:"type:jsonb"`
	CreatedAt time.Time              `json:"created_at" gorm:"index"`
}

func (AuditLog) TableName() string

// ============================================================================
// FILE: modules/admin/repository/audit_log_repository.go
// ============================================================================
package repository

import (
	"context"

	"github.com/yourusername/go-auth/modules/admin/models"
	"github.com/yourusername/go-auth/storage"
)

type AuditLogRepository struct {
	storage storage.Storage
}

func NewAuditLogRepository(storage storage.Storage) *AuditLogRepository

func (r *AuditLogRepository) Create(ctx context.Context, log *models.AuditLog) error

func (r *AuditLogRepository) List(ctx context.Context, limit, offset int) ([]*models.AuditLog, error)

func (r *AuditLogRepository) FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error)

func (r *AuditLogRepository) FindByAction(ctx context.Context, action string, limit, offset int) ([]*models.AuditLog, error)

// ============================================================================
// FILE: modules/admin/service/admin_service.go
// ============================================================================
package service

import (
	"context"

	coreRepo "github.com/yourusername/go-auth/core/repository"
	"github.com/yourusername/go-auth/modules/admin/repository"
)

type AdminService struct {
	userRepo     *coreRepo.UserRepository
	auditRepo    *repository.AuditLogRepository
	config       *Config
}

type Config struct {
	AdminRoles []string
}

func NewAdminService(
	userRepo *coreRepo.UserRepository,
	auditRepo *repository.AuditLogRepository,
	config *Config,
) *AdminService

func (s *AdminService) ListUsers(ctx context.Context, limit, offset int) (interface{}, error)

func (s *AdminService) GetUser(ctx context.Context, userID string) (interface{}, error)

func (s *AdminService) DeleteUser(ctx context.Context, userID string, adminID string) error

func (s *AdminService) SuspendUser(ctx context.Context, userID string, adminID string) error

func (s *AdminService) ActivateUser(ctx context.Context, userID string, adminID string) error

func (s *AdminService) GetAuditLogs(ctx context.Context, filters map[string]interface{}, limit, offset int) (interface{}, error)

func (s *AdminService) LogAction(ctx context.Context, userID, action, resource string, metadata map[string]interface{}) error

func (s *AdminService) IsAdmin(ctx context.Context, userID string) (bool, error)

// ============================================================================
// FILE: modules/admin/handlers/handlers.go
// ============================================================================
package handlers

import (
	"github.com/yourusername/go-auth/modules/admin/service"
)

type Handlers struct {
	adminService *service.AdminService
}

func NewHandlers(adminService *service.AdminService) *Handlers

// ============================================================================
// FILE: modules/admin/handlers/users.go
// ============================================================================
package handlers

import "net/http"

type ListUsersResponse struct {
	Users      []interface{} `json:"users"`
	Total      int           `json:"total"`
	Limit      int           `json:"limit"`
	Offset     int           `json:"offset"`
}

func (h *Handlers) ListUsers(w http.ResponseWriter, r *http.Request)

func (h *Handlers) GetUser(w http.ResponseWriter, r *http.Request)

func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request)

func (h *Handlers) SuspendUser(w http.ResponseWriter, r *http.Request)

func (h *Handlers) ActivateUser(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: modules/admin/handlers/audit_logs.go
// ============================================================================
package handlers

import "net/http"

type AuditLogsResponse struct {
	Logs   []interface{} `json:"logs"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

func (h *Handlers) GetAuditLogs(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: modules/admin/middleware.go
// ============================================================================
package admin

import "net/http"

func (m *Module) requireAdminMiddleware(next http.Handler) http.Handler

// ============================================================================
// FILE: modules/passkey/module.go
// ============================================================================
package passkey

import (
	"context"
	"net/http"

	"github.com/yourusername/go-auth"
	"github.com/yourusername/go-auth/modules/passkey/handlers"
	"github.com/yourusername/go-auth/modules/passkey/repository"
	"github.com/yourusername/go-auth/modules/passkey/service"
)

type Module struct {
	config      *Config
	repo        *repository.PasskeyRepository
	service     *service.WebAuthnService
	handlers    *handlers.Handlers
}

type Config struct {
	RPDisplayName string
	RPID          string
	RPOrigin      string
}

func New() *Module

func (m *Module) Name() string

func (m *Module) Init(ctx context.Context, deps auth.ModuleDependencies) error

func (m *Module) Handler() (http.Handler, string)

func (m *Module) Middlewares() []func(http.Handler) http.Handler

func (m *Module) Models() []interface{}

func (m *Module) Hooks() auth.Hooks

func (m *Module) Dependencies() []string

// ============================================================================
// FILE: modules/passkey/models/passkey.go
// ============================================================================
package models

import "time"

type Passkey struct {
	ID              string    `json:"id" gorm:"primaryKey"`
	UserID          string    `json:"user_id" gorm:"not null;index"`
	CredentialID    []byte    `json:"-" gorm:"not null;uniqueIndex"`
	PublicKey       []byte    `json:"-" gorm:"not null"`
	Counter         uint32    `json:"counter"`
	AAGUID          []byte    `json:"-"`
	Name            string    `json:"name"`
	LastUsedAt      *time.Time `json:"last_used_at"`
	CreatedAt       time.Time `json:"created_at"`
}

func (Passkey) TableName() string

// ============================================================================
// FILE: modules/passkey/repository/passkey_repository.go
// ============================================================================
package repository

import (
	"context"

	"github.com/yourusername/go-auth/modules/passkey/models"
	"github.com/yourusername/go-auth/storage"
)

type PasskeyRepository struct {
	storage storage.Storage
}

func NewPasskeyRepository(storage storage.Storage) *PasskeyRepository

func (r *PasskeyRepository) Create(ctx context.Context, passkey *models.Passkey) error

func (r *PasskeyRepository) FindByUserID(ctx context.Context, userID string) ([]*models.Passkey, error)

func (r *PasskeyRepository) FindByCredentialID(ctx context.Context, credentialID []byte) (*models.Passkey, error)

func (r *PasskeyRepository) Update(ctx context.Context, passkey *models.Passkey) error

func (r *PasskeyRepository) Delete(ctx context.Context, id string) error

// ============================================================================
// FILE: modules/passkey/service/webauthn_service.go
// ============================================================================
package service

import (
	"context"

	"github.com/yourusername/go-auth/modules/passkey/models"
	"github.com/yourusername/go-auth/modules/passkey/repository"
)

type WebAuthnService struct {
	repo   *repository.PasskeyRepository
	config *Config
}

type Config struct {
	RPDisplayName string
	RPID          string
	RPOrigin      string
}

func NewWebAuthnService(repo *repository.PasskeyRepository, config *Config) *WebAuthnService

func (s *WebAuthnService) BeginRegistration(ctx context.Context, userID, userName string) (interface{}, error)

func (s *WebAuthnService) FinishRegistration(ctx context.Context, userID string, response interface{}) error

func (s *WebAuthnService) BeginLogin(ctx context.Context, userID string) (interface{}, error)

func (s *WebAuthnService) FinishLogin(ctx context.Context, response interface{}) (string, error)

func (s *WebAuthnService) ListPasskeys(ctx context.Context, userID string) ([]*models.Passkey, error)

func (s *WebAuthnService) DeletePasskey(ctx context.Context, userID, passkeyID string) error

// ============================================================================
// FILE: modules/passkey/handlers/handlers.go
// ============================================================================
package handlers

import (
	"github.com/yourusername/go-auth/modules/passkey/service"
)

type Handlers struct {
	webauthnService *service.WebAuthnService
}

func NewHandlers(webauthnService *service.WebAuthnService) *Handlers

// ============================================================================
// FILE: modules/passkey/handlers/register.go
// ============================================================================
package handlers

import "net/http"

type BeginRegistrationResponse struct {
	Options interface{} `json:"options"`
}

func (h *Handlers) BeginRegistration(w http.ResponseWriter, r *http.Request)

type FinishRegistrationRequest struct {
	Response interface{} `json:"response"`
}

func (h *Handlers) FinishRegistration(w http.ResponseWriter, r *http.Request)

// ============================================================================
// FILE: modules/passkey/handlers/authenticate.go
// ============================================================================
package handlers

import "net/http"

type BeginLoginResponse struct {
	Options interface{} `json:"options"`
}

func (h *Handlers) BeginLogin(w http.ResponseWriter, r *http.Request)

type FinishLoginRequest struct {
	Response interface{} `json:"response"`
}

type FinishLoginResponse struct {
	Token string      `json:"token"`
	User  interface{} `json:"user"`
}

func (h *Handlers) FinishLogin(w http.ResponseWriter, r *http.Request)

func (h *Handlers) ListPasskeys(w http.ResponseWriter, r *http.Request)

func (h *Handlers) DeletePasskey(w http.ResponseWriter, r *http.Request)

// ============================================================================
// USAGE EXAMPLE 1: Standalone with stdlib http
// ============================================================================
// FILE: examples/stdlib/main.go
package main

import (
	"context"
	"log"
	"net/http"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/yourusername/go-auth"
	gormstorage "github.com/yourusername/go-auth/storage/gorm"
	"github.com/yourusername/go-auth/modules/twofactor"
	"github.com/yourusername/go-auth/modules/csrf"
)

func main() {
	// Setup database
	db, err := gorm.Open(postgres.Open("postgres://localhost/authdb"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Create storage
	storage := gormstorage.NewStorage(db)

	// Create auth instance
	authLib, err := auth.New(&auth.Config{
		Storage:         storage,
		SecretKey:       "your-secret-key",
		SessionDuration: 24 * 3600, // 24 hours
		AutoMigrate:     true,
		BasePath:        "/auth",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Add modules
	authLib.Use(twofactor.New())
	authLib.Use(csrf.New())

	// Initialize
	if err := authLib.Initialize(context.Background()); err != nil {
		log.Fatal(err)
	}

	// Setup routes
	mux := http.NewServeMux()

	// Mount auth routes
	mux.Handle("/auth/", authLib.Handler())

	// Protected route
	mux.Handle("/api/dashboard", authLib.RequireAuth(http.HandlerFunc(dashboard)))

	// Public route
	mux.HandleFunc("/", home)

	log.Println("Server running on :8080")
	http.ListenAndServe(":8080", mux)
}

func dashboard(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.GetUser(r.Context())
	auth.JSON(w, 200, map[string]interface{}{
		"message": "Dashboard",
		"user":    user,
	})
}

func home(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Home"))
}

// ============================================================================
// USAGE EXAMPLE 2: With Gin
// ============================================================================
// FILE: examples/gin/main.go
package main

import (
	"context"
	"log"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/yourusername/go-auth"
	gormstorage "github.com/yourusername/go-auth/storage/gorm"
	"github.com/yourusername/go-auth/modules/twofactor"
)

func main() {
	db, _ := gorm.Open(postgres.Open("postgres://localhost/authdb"), &gorm.Config{})
	storage := gormstorage.NewStorage(db)

	authLib, _ := auth.New(&auth.Config{
		Storage:     storage,
		SecretKey:   "secret",
		AutoMigrate: true,
	})

	authLib.Use(twofactor.New())
	authLib.Initialize(context.Background())

	r := gin.Default()

	// Mount auth routes using Gin's adapter
	r.Any("/auth/*path", gin.WrapH(authLib.Handler()))

	// Protected route
	api := r.Group("/api")
	api.Use(func(c *gin.Context) {
		// Wrap the auth middleware for Gin
		handler := authLib.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Request = r
			c.Next()
		}))
		handler.ServeHTTP(c.Writer, c.Request)
	})
	{
		api.GET("/dashboard", func(c *gin.Context) {
			user, _ := auth.GetUser(c.Request.Context())
			c.JSON(200, gin.H{"user": user})
		})
	}

	r.Run(":8080")
}

// ============================================================================
// USAGE EXAMPLE 3: With Echo
// ============================================================================
// FILE: examples/echo/main.go
package main

import (
	"context"

	"github.com/labstack/echo/v4"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/yourusername/go-auth"
	gormstorage "github.com/yourusername/go-auth/storage/gorm"
)

func main() {
	db, _ := gorm.Open(postgres.Open("postgres://localhost/authdb"), &gorm.Config{})
	storage := gormstorage.NewStorage(db)

	authLib, _ := auth.New(&auth.Config{
		Storage:     storage,
		SecretKey:   "secret",
		AutoMigrate: true,
	})

	authLib.Initialize(context.Background())

	e := echo.New()

	// Mount auth routes
	e.Any("/auth/*", echo.WrapHandler(authLib.Handler()))

	// Protected routes
	api := e.Group("/api")
	api.Use(echo.WrapMiddleware(authLib.RequireAuth))
	api.GET("/dashboard", func(c echo.Context) error {
		user, _ := auth.GetUser(c.Request().Context())
		return c.JSON(200, map[string]interface{}{"user": user})
	})

	e.Start(":8080")
}

// ============================================================================
// USAGE EXAMPLE 4: With Chi
// ============================================================================
// FILE: examples/chi/main.go
package main

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/yourusername/go-auth"
	gormstorage "github.com/yourusername/go-auth/storage/gorm"
)

func main() {
	db, _ := gorm.Open(postgres.Open("postgres://localhost/authdb"), &gorm.Config{})
	storage := gormstorage.NewStorage(db)

	authLib, _ := auth.New(&auth.Config{
		Storage:     storage,
		SecretKey:   "secret",
		AutoMigrate: true,
	})

	authLib.Initialize(context.Background())

	r := chi.NewRouter()

	// Mount auth routes (Chi natively supports net/http.Handler)
	r.Mount("/auth", authLib.Handler())

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(authLib.RequireAuth)
		r.Get("/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
			user, _ := auth.GetUser(r.Context())
			auth.JSON(w, 200, map[string]interface{}{"user": user})
		})
	})

	http.ListenAndServe(":8080", r)
}

// ============================================================================
// USAGE EXAMPLE 5: Custom Storage Implementation
// ============================================================================
// FILE: examples/custom-storage/main.go
package main

import (
	"context"
	"database/sql"

	"github.com/yourusername/go-auth"
	"github.com/yourusername/go-auth/storage"
)

// MyCustomStorage implements storage.Storage
type MyCustomStorage struct {
	db *sql.DB
}

func NewMyCustomStorage(db *sql.DB) storage.Storage {
	return &MyCustomStorage{db: db}
}

func (s *MyCustomStorage) DB() interface{} {
	return s.db
}

func (s *MyCustomStorage) AutoMigrate(models ...interface{}) error {
	// Implement custom migration logic
	// Or use golang-migrate, goose, etc.
	return nil
}

func (s *MyCustomStorage) Transaction(ctx context.Context, fn func(tx storage.Storage) error) error {
	// Implement transaction logic
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	txStorage := &MyCustomStorage{db: s.db}
	if err := fn(txStorage); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (s *MyCustomStorage) Query() storage.QueryBuilder {
	// Return custom query builder
	return nil
}

func main() {
	db, _ := sql.Open("postgres", "...")
	storage := NewMyCustomStorage(db)

	authLib, _ := auth.New(&auth.Config{
		Storage:   storage,
		SecretKey: "secret",
	})

	// Use as normal
	_ = authLib
}

// ============================================================================
// USAGE EXAMPLE 6: With Hooks
// ============================================================================
// FILE: examples/hooks/main.go
package main

import (
	"context"
	"log"

	"github.com/yourusername/go-auth"
	"github.com/yourusername/go-auth/core/models"
)

func main() {
	authLib, _ := auth.New(&auth.Config{
		// ... storage config
		Hooks: auth.Hooks{
			AfterSignup: []auth.HookFunc{
				func(ctx context.Context, data *auth.HookData) error {
					user := data.User.(*models.User)
					log.Printf("New user signed up: %s", user.Email)
					// Send welcome email
					return nil
				},
			},
			AfterLogin: []auth.HookFunc{
				func(ctx context.Context, data *auth.HookData) error {
					user := data.User.(*models.User)
					log.Printf("User logged in: %s", user.Email)
					// Log activity
					return nil
				},
			},
		},
	})

	_ = authLib
}

// ============================================================================
// USAGE EXAMPLE 7: Module Configuration
// ============================================================================
// FILE: examples/module-config/main.go
package main

import (
	"github.com/yourusername/go-auth"
	"github.com/yourusername/go-auth/modules/twofactor"
	"github.com/yourusername/go-auth/modules/csrf"
)

func main() {
	authLib, _ := auth.New(&auth.Config{
		// ... other config
		ModuleConfigs: map[string]interface{}{
			"twofactor": &twofactor.Config{
				Issuer:     "MyApp",
				CodeLength: 6,
			},
			"csrf": &csrf.Config{
				TokenLength: 32,
				CookieName:  "_csrf",
				HeaderName:  "X-CSRF-Token",
			},
		},
	})

	authLib.Use(twofactor.New())
	authLib.Use(csrf.New())

	_ = authLib
}