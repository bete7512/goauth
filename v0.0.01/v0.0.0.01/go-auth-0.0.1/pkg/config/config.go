package config

import (
	"bytes"
	"context"
	"net/http"
	"time"
	// "golang.org/x/mod/sumdb/storage"
	// "github.com/nodeum-io/nodeum-plugins/storage"
)

type RouteInfo struct {
	Method  string
	Path    string
	Name    string
	Handler http.HandlerFunc
}

type Module interface {
	// Name returns the module identifier
	Name() string

	// Init initializes the module with dependencies
	Init(ctx context.Context, deps ModuleDependencies) error

	// Handler returns the HTTP handler and mount path
	Routes() []RouteInfo

	// Middlewares returns HTTP middlewares
	Middlewares() []func(http.Handler) http.Handler

	// Models returns database models for migration
	Models() []interface{}

	// Hooks returns lifecycle hooks
	Hooks() Hooks

	// Dependencies returns required module names
	Dependencies() []string
}

type ModuleDependencies struct {
	// Storage storage.Storage
	Config *Config
	// Logger  Logger
	// Adapter Adapter
	//
	// Events  EventBus
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
	Data    interface{}
	Request *http.Request
	Buffer  *bytes.Buffer
}

type Config struct {
	// Storage backend
	// Storage storage.Storage
	// 

	// Security
	SecretKey       string
	SessionDuration time.Duration

	// Migration
	AutoMigrate bool

	// Base path for all routes
	BasePath string

	// Module-specific configurations
	ModuleConfigs map[string]interface{}

	// Hooks
	Hooks Hooks
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// if c.Storage == nil {
	// 	return NewConfigErr("storage backend is required")
	// }
	if c.SecretKey == "" {
		return NewConfigErr("secret key is required")
	}
	if c.SessionDuration <= 0 {
		return NewConfigErr("invalid session duration")
	}
	if c.BasePath == "" {
		c.BasePath = "/auth"
	}
	if c.ModuleConfigs == nil {
		c.ModuleConfigs = make(map[string]interface{})
	}
	return nil
}

func (c *Config) GetModuleConfig(name string) interface{} {
	return c.ModuleConfigs[name]
}
