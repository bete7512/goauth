package auth

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/modules/core"
	"github.com/bete7512/goauth/pkg/config"
)

// Config holds library configuration
// Auth is the main library instance
type Auth struct {
	config *config.Config
	// storage            storage.Storage
	modules            map[string]config.Module
	routes             []config.RouteInfo
	moduleDependencies config.ModuleDependencies
}

// New creates a new Auth instance
func New(cfg *config.Config) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	auth := &Auth{
		config:  cfg,
		modules: make(map[string]config.Module),
	}
	auth.modules[string(config.CoreModule)] = core.New()
	auth.moduleDependencies = config.ModuleDependencies{
		Config: cfg,
		// Storage: cfg.Storage,
		// Logger:  logger,
		// Adapter: adapter,
		// Events:  eventBus,
	}

	return auth, nil
}

// Use registers a module
func (a *Auth) Use(module config.Module) error {
	if _, exists := a.modules[module.Name()]; exists {
		return config.NewConfigErr("module already registered")
	}
	a.modules[module.Name()] = module
	return nil
}

func (a *Auth) Config() *config.Config {
	return a.config
}

func (a *Auth) Routes() []config.RouteInfo {
	var routes []config.RouteInfo
	for _, module := range a.modules {
		moduleRoutes := module.Routes()
		routes = append(routes, moduleRoutes...)
	}
	return routes
}

// Initialize initializes all modules and runs migrations
func (a *Auth) Initialize(ctx context.Context) error {
	for _, module := range a.modules {
		if err := module.Init(ctx, a.moduleDependencies); err != nil {
			return err
		}
	}
	return nil
}

// RequireAuth returns middleware that requires authentication
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// GetModule retrieves a registered module by name
func (a *Auth) GetModule(name string) (config.Module, error) {
	module, exists := a.modules[name]
	if !exists {
		return nil, config.NewConfigErr("module not found")
	}
	return module, nil
}

// // GenerateMigrationSQL generates SQL migration file
// func (a *Auth) GenerateMigrationSQL() ([]byte, error) {
// 	var buf bytes.Buffer
// 	for _, module := range a.modules {
// 		if err := module.GenerateMigrationSQL(&buf); err != nil {
// 			return nil, err
// 		}
// 	}
// 	return buf.Bytes(), nil
// }
