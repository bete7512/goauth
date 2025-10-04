package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/internal/events"
	"github.com/bete7512/goauth/internal/middleware"
	"github.com/bete7512/goauth/internal/modules/core"
	"github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/pkg/config"
)

/*
TODO: in future events can be
*/
// Auth is the main library instance
type Auth struct {
	config                   *config.Config
	storage                  config.Storage
	modules                  map[string]config.Module
	routes                   []config.RouteInfo
	commonModuleDependencies config.ModuleDependencies
	eventBus                 *events.EventBus
	middlewareManager        *middleware.Manager
	logger                   events.Logger
	initialized              bool
}

// New creates a new Auth instance
func New(cfg *config.Config) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Initialize logger
	logger := &events.DefaultLogger{}

	// Initialize event bus with custom async backend if provided
	var eventBus *events.EventBus
	if cfg.AsyncBackend != nil {
		// Wrap config.AsyncBackend to match events.AsyncBackend interface
		asyncBackend := &asyncBackendAdapter{backend: cfg.AsyncBackend}
		eventBus = events.NewEventBusWithBackend(logger, asyncBackend)
	} else {
		// Use default worker pool
		eventBus = events.NewEventBus(logger)
	}

	// Initialize middleware manager
	middlewareManager := middleware.NewManager()

	// Register global middlewares if CORS is enabled
	if cfg.CORS != nil && cfg.CORS.Enabled {
		middlewareManager.Register(middleware.MiddlewareConfig{
			Name:       "cors",
			Middleware: middleware.CORS(cfg.CORS.AllowedOrigins, cfg.CORS.AllowedMethods),
			Priority:   100,
			Global:     true,
		})
	}

	// Add request ID middleware
	middlewareManager.Register(middleware.MiddlewareConfig{
		Name:       "auth.add-request-id",
		Middleware: middleware.RequestID(),
		Priority:   90,
		Global:     true,
	})

	auth := &Auth{
		config:            cfg,
		storage:           cfg.Storage,
		modules:           make(map[string]config.Module),
		eventBus:          eventBus,
		middlewareManager: middlewareManager,
		logger:            logger,
	}

	// Setup module dependencies
	var configLogger config.Logger
	if cfg.Logger != nil {
		configLogger = cfg.Logger
	} else {
		configLogger = logger
	}

	eventBusAdapter := events.NewEventBusAdapter(eventBus)
	auth.commonModuleDependencies = config.ModuleDependencies{
		Storage:           cfg.Storage,
		Config:            cfg,
		Logger:            configLogger,
		Events:            eventBusAdapter,
		MiddlewareManager: middlewareManager,
	}
	if auth.config.ModuleConfigs[string(config.CoreModule)] == nil {
		coreConfig := &core.Config{}
		if auth.storage != nil {
			if auth.storage.GetRepository(string(config.CoreUserRepository)) == nil {
				return nil, fmt.Errorf("core.user repository is not found storage is not connected correctly")
			}
			if auth.storage.GetRepository(string(config.CoreSessionRepository)) == nil {
				return nil, fmt.Errorf("core.session repository is not found storage is not connected correctly")
			}
			if auth.storage.GetRepository(string(config.CoreTokenRepository)) == nil {
				return nil, fmt.Errorf("core.token repository is not found storage is not connected correctly")
			}
			coreConfig.UserRepository = auth.storage.GetRepository(string(config.CoreUserRepository)).(models.UserRepository)
			coreConfig.SessionRepository = auth.storage.GetRepository(string(config.CoreSessionRepository)).(models.SessionRepository)
			coreConfig.TokenRepository = auth.storage.GetRepository(string(config.CoreTokenRepository)).(models.TokenRepository)

		}
		coreModule := core.New(coreConfig)
		auth.modules[coreModule.Name()] = coreModule
	}

	return auth, nil
}

// Use registers a module (must be called before Initialize)
func (a *Auth) Use(module config.Module) error {
	if a.initialized {
		return fmt.Errorf("cannot add module after initialization")
	}

	if _, exists := a.modules[module.Name()]; exists {
		return fmt.Errorf("module already registered: %s", module.Name())
	}

	// Check dependencies
	deps := module.Dependencies()
	for _, dep := range deps {
		if _, exists := a.modules[dep]; !exists {
			return fmt.Errorf("module %s requires dependency %s which is not registered", module.Name(), dep)
		}
	}

	a.modules[module.Name()] = module
	a.logger.Info("Module registered", "name", module.Name())
	return nil
}

func (a *Auth) Config() *config.Config {
	return a.config
}

// Routes returns all registered routes with middlewares applied
func (a *Auth) Routes() []config.RouteInfo {
	if !a.initialized {
		a.logger.Warn("Routes called before initialization")
		return nil
	}

	// Return routes with middlewares applied
	routesWithMiddleware := make([]config.RouteInfo, len(a.routes))
	for i, route := range a.routes {
		// Apply middlewares to route handler
		handler := a.middlewareManager.Apply(route.Name, http.HandlerFunc(route.Handler))
		routesWithMiddleware[i] = config.RouteInfo{
			Name:    route.Name,
			Path:    route.Path,
			Method:  route.Method,
			Handler: handler.ServeHTTP,
		}
	}

	return routesWithMiddleware
}

// Initialize initializes all modules and runs migrations
func (a *Auth) Initialize(ctx context.Context) error {
	if a.initialized {
		return fmt.Errorf("auth already initialized")
	}

	// Populate repositories from storage to dependencies
	// Modules can access repositories via deps.Repositories or deps.Storage.GetRepository()
	// for _, repoName := range []string{
	// 	string(config.CoreUserRepository),
	// 	string(config.CoreSessionRepository),
	// 	string(config.AdminAuditLogRepository),
	// 	// Add more repository constants as needed
	// } {
	// 	a.commonModuleDependencies.Repositories[repoName] = a.storage.GetRepository(repoName)
	// }

	// Collect all models from modules
	var allModels []interface{}
	for _, module := range a.modules {
		models := module.Models()
		allModels = append(allModels, models...)
	}

	// Run migrations if enabled
	if a.config.AutoMigrate && len(allModels) > 0 {
		a.logger.Info("Running auto-migrations", "models", len(allModels))
		if err := a.storage.Migrate(ctx, allModels); err != nil {
			return fmt.Errorf("failed to run migrations: %w", err)
		}
	}

	// Initialize all modules
	for name, module := range a.modules {
		a.logger.Info("Initializing module", "name", name)
		if err := module.Init(ctx, a.commonModuleDependencies); err != nil {
			return fmt.Errorf("failed to initialize module %s: %w", name, err)
		}

		// Register module hooks
		if err := module.RegisterHooks(a.commonModuleDependencies.Events); err != nil {
			return fmt.Errorf("failed to register hooks for module %s: %w", name, err)
		}

		// Register module middlewares
		for _, mwConfig := range module.Middlewares() {
			a.middlewareManager.Register(middleware.MiddlewareConfig{
				Name:        mwConfig.Name,
				Middleware:  mwConfig.Middleware,
				Priority:    mwConfig.Priority,
				ApplyTo:     mwConfig.ApplyTo,
				ExcludeFrom: mwConfig.ExcludeFrom,
				Global:      mwConfig.Global,
			})
		}
	}

	// Build routes
	a.routes = a.buildRoutes()

	a.initialized = true
	a.logger.Info("Auth initialization completed", "modules", len(a.modules), "routes", len(a.routes))
	return nil
}

// buildRoutes collects and processes routes from all modules
func (a *Auth) buildRoutes() []config.RouteInfo {
	var routes []config.RouteInfo
	for _, module := range a.modules {
		moduleRoutes := module.Routes()
		for _, route := range moduleRoutes {
			// Prepend base path
			route.Path = a.config.BasePath + route.Path
			routes = append(routes, route)
		}
	}
	return routes
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
		return nil, config.ErrConfig("module not found")
	}
	return module, nil
}

// Close gracefully shuts down the auth system
// Closes event bus, async backend, and storage connections
func (a *Auth) Close() error {
	// Close event bus (which closes async backend)
	if a.eventBus != nil {
		if err := a.eventBus.Close(); err != nil {
			return fmt.Errorf("failed to close event bus: %w", err)
		}
	}

	// Close storage
	if a.storage != nil {
		if err := a.storage.Close(); err != nil {
			return fmt.Errorf("failed to close storage: %w", err)
		}
	}

	return nil
}

// asyncBackendAdapter adapts config.AsyncBackend to events.AsyncBackend
type asyncBackendAdapter struct {
	backend config.AsyncBackend
}

func (a *asyncBackendAdapter) Publish(ctx context.Context, eventType events.EventType, event *events.Event) error {
	return a.backend.Publish(ctx, string(eventType), event)
}

func (a *asyncBackendAdapter) Close() error {
	return a.backend.Close()
}

func (a *asyncBackendAdapter) Name() string {
	return a.backend.Name()
}
