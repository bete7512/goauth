package config

import (
	"context"
	"net/http"
	"time"
)

type RouteInfo struct {
	Method  string
	Path    string
	Name    string // Unique route identifier (e.g., "core.login", "admin.users.list")
	Handler http.HandlerFunc
}

type Module interface {
	// Name returns the module identifier
	Name() string

	// Init initializes the module with dependencies
	Init(ctx context.Context, deps ModuleDependencies) error

	// Routes returns HTTP routes with unique names
	Routes() []RouteInfo

	// Middlewares returns middleware configurations for this module
	Middlewares() []MiddlewareConfig

	// Models returns database models for migration
	Models() []interface{}

	// RegisterHooks registers event handlers for this module
	RegisterHooks(events EventBus) error

	// Dependencies returns required module names
	Dependencies() []string
}

type ModuleDependencies struct {
	Storage           Storage
	Config            *Config
	Logger            Logger
	Events            EventBus
	MiddlewareManager MiddlewareManager
}

// MiddlewareConfig for modules to define middleware application
type MiddlewareConfig struct {
	Name        string
	Middleware  func(http.Handler) http.Handler
	Priority    int
	ApplyTo     []string // Route names or patterns
	ExcludeFrom []string // Route names or patterns to exclude
	Global      bool     // Apply to all routes
}

// Storage interface placeholder (will be implemented separately)
type Storage interface {
	Initialize(ctx context.Context) error
	Close() error
	Migrate(ctx context.Context, models []interface{}) error
	BeginTx(ctx context.Context) (Transaction, error)
	DB() interface{}
	Repository(model interface{}) Repository
}

// Transaction interface for database transactions
type Transaction interface {
	Commit() error
	Rollback() error
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

// EventBus interface for event handling
type EventBus interface {
	Subscribe(eventType string, handler EventHandler, opts ...interface{})
	Emit(ctx context.Context, eventType string, data interface{}) error
	EmitSync(ctx context.Context, eventType string, data interface{}) error
}

// EventHandler handles events
type EventHandler func(ctx context.Context, event interface{}) error

// MiddlewareManager manages middleware application
type MiddlewareManager interface {
	Apply(routeName string, handler http.Handler) http.Handler
	ApplyGlobal(handler http.Handler) http.Handler
}

// Logger interface for structured logging
type Logger interface {
	Info(msg string, args ...interface{})
	Trace(msg string, args ...interface{})
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
}

type Config struct {
	// Storage backend
	Storage Storage

	// Security
	SecretKey       string
	SessionDuration time.Duration

	// Migration
	AutoMigrate bool

	// Base path for all routes
	BasePath string

	// Module-specific configurations
	ModuleConfigs map[string]interface{}

	// Logger
	Logger Logger

	// CORS Configuration
	CORS *CORSConfig
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	Enabled          bool
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	AllowCredentials bool
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Storage == nil {
		return NewConfigErr("storage backend is required")
	}
	if c.SecretKey == "" {
		return NewConfigErr("secret key is required")
	}
	if c.SessionDuration <= 0 {
		c.SessionDuration = 24 * time.Hour // Default to 24 hours
	}
	if c.BasePath == "" {
		c.BasePath = "/auth"
	}
	if c.ModuleConfigs == nil {
		c.ModuleConfigs = make(map[string]interface{})
	}

	// Set default CORS if not provided
	if c.CORS == nil {
		c.CORS = &CORSConfig{
			Enabled:          false,
			AllowedOrigins:   []string{"*"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "Authorization"},
			AllowCredentials: true,
		}
	}

	return nil
}

func (c *Config) GetModuleConfig(name string) interface{} {
	return c.ModuleConfigs[name]
}
