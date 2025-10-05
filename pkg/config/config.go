package config

import (
	"context"
	"net/http"
	"time"

	// "github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/types"
)

type RouteInfo struct {
	Name    string // Unique route identifier (e.g., "core.login", "admin.users.list")
	Method  string
	Path    string
	Handler http.HandlerFunc
}

type ModuleMigration struct {
	ID   string
	Up   string
	Down string
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
	RegisterHooks(events types.EventBus) error

	// Dependencies returns required module names
	Dependencies() []string

	// SwaggerSpec returns module's swagger spec (YAML or JSON)
	SwaggerSpec() []byte // Returns module's swagger spec (YAML or JSON)

}

type ModuleDependencies struct {
	Storage           Storage
	Config            *Config
	Logger            logger.Logger
	Events            types.EventBus
	MiddlewareManager MiddlewareManager
	SecurityManager   *security.SecurityManager
	Options           interface{}
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

// MiddlewareManager manages middleware application
type MiddlewareManager interface {
	Apply(routeName string, handler http.Handler) http.Handler
	ApplyGlobal(handler http.Handler) http.Handler
}

type Config struct {
	// Storage backend
	Storage Storage

	// Migration
	AutoMigrate bool

	// Base path for all routes
	BasePath string

	// Module-specific configurations
	ModuleConfigs map[string]interface{}

	// Logger - Users can provide their own logger implementation
	// If nil, a default logrus logger will be used
	Logger logger.Logger

	// CORS Configuration
	CORS *CORSConfig

	// AsyncBackend for async event processing
	// If nil, uses default worker pool (10 workers, 1000 queue size)
	// Users can provide Redis, RabbitMQ, Kafka, or custom implementations
	AsyncBackend types.AsyncBackend

	// Security
	Security types.SecurityConfig
	// Swagger
	SwaggerConfig *types.SwaggerConfig
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
		return ErrConfig("storage backend is required")
	}
	if c.Security.JwtSecretKey == "" {
		return ErrConfig("jwt secret key is required")
	}
	if c.Security.EncryptionKey == "" {
		return ErrConfig("encryption key is required")
	}
	if c.Security.HashSaltLength <= 0 {
		c.Security.HashSaltLength = 10 // Default to 10
	}
	if c.Security.SessionDuration <= 0 {
		c.Security.SessionDuration = 24 * time.Hour // Default to 24 hours
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
