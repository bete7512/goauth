package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/internal/events"
	"github.com/bete7512/goauth/internal/middleware"
	"github.com/bete7512/goauth/internal/modules/core"
	"github.com/bete7512/goauth/internal/modules/core/middlewares"
	"github.com/bete7512/goauth/internal/modules/stateless"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type Auth struct {
	config             *config.Config
	storage            config.Storage
	modules            map[string]config.Module
	routes             []config.RouteInfo
	moduleDependencies config.ModuleDependencies
	eventBus           *events.EventBus
	middlewareManager  *middleware.Manager
	logger             logger.Logger
	initialized        bool
}

// New creates a new Auth instance
// Note: After creating Auth, you should call Use() to register auth modules:
//   - auth.Use(session.New(...)) for session-based authentication
//   - auth.Use(stateless.New(...)) for stateless JWT authentication
func New(cfg *config.Config) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Initialize logger
	// Use provided logger from config, or create default logrus logger
	var authLogger logger.Logger
	if cfg.Logger != nil {
		authLogger = cfg.Logger
	} else {
		// Use logrus as default logger
		authLogger = logger.NewLogrusLogger()
	}

	// Initialize event bus with custom async backend if provided
	var eventBus *events.EventBus
	if cfg.AsyncBackend != nil {
		// Wrap config.AsyncBackend to match events.AsyncBackend interface
		asyncBackend := &asyncBackendAdapter{backend: cfg.AsyncBackend}
		eventBus = events.NewEventBusWithBackend(authLogger, asyncBackend)
	} else {
		// Use default worker pool
		eventBus = events.NewEventBus(authLogger)
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/auth"
	}

	// Initialize middleware manager
	middlewareManager := middleware.NewManager()

	// Register global middlewares if CORS is enabled
	if cfg.CORS != nil && cfg.CORS.Enabled {
		middlewareManager.Register(middleware.MiddlewareConfig{
			Name:       "cors",
			Middleware: middleware.CORS(cfg.CORS.AllowedOrigins, cfg.CORS.AllowedMethods, cfg.CORS.AllowedHeaders),
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
		logger:            authLogger,
	}

	// Setup module dependencies - use the same logger for modules
	var configLogger logger.Logger
	if cfg.Logger != nil {
		configLogger = cfg.Logger
	} else {
		configLogger = authLogger
	}

	eventBusAdapter := events.NewEventBusAdapter(eventBus)
	auth.moduleDependencies = config.ModuleDependencies{
		Storage:           cfg.Storage,
		Config:            cfg,
		Logger:            configLogger,
		Events:            eventBusAdapter,
		MiddlewareManager: middlewareManager,
	}

	// Auto-register core module if not already configured
	// Core module will get storage from deps.Storage.Core() during initialization
	if auth.config.ModuleConfigs[string(types.CoreModule)] == nil {
		coreConfig := &config.CoreConfig{}

		if auth.config.Core != nil {
			coreConfig.RequireEmailVerification = auth.config.Core.RequireEmailVerification
			coreConfig.RequirePhoneVerification = auth.config.Core.RequirePhoneVerification
			coreConfig.RequireUserName = auth.config.Core.RequireUserName
			coreConfig.RequirePhoneNumber = auth.config.Core.RequirePhoneNumber
		}

		// Pass nil for customStorage - core will get storage from deps.Storage.Core()
		coreModule := core.New(coreConfig, nil)
		auth.modules[coreModule.Name()] = coreModule
	}

	return auth, nil
}

// Use registers a module (must be called before Initialize)
// For authentication, use ONE of:
//   - session.New(...) for session-based authentication
//   - stateless.New(...) for stateless JWT authentication
//
// Note: You cannot use both session and stateless modules together.
// If neither is registered, stateless will be used as default.
//
// IMPORTANT: Registering both session and stateless modules will panic.
func (a *Auth) Use(module config.Module) error {
	if a.initialized {
		return fmt.Errorf("cannot add module after initialization")
	}

	if _, exists := a.modules[module.Name()]; exists {
		return fmt.Errorf("module already registered: %s", module.Name())
	}

	// Validate that only one auth module (session or stateless) is registered
	// This is a hard failure - panic if both are registered
	moduleName := module.Name()
	if moduleName == string(types.SessionModule) || moduleName == string(types.StatelessModule) {
		_, hasSession := a.modules[string(types.SessionModule)]
		_, hasStateless := a.modules[string(types.StatelessModule)]

		if moduleName == string(types.SessionModule) && hasStateless {
			panic("goauth: cannot register session module: stateless module is already registered. Only one auth module (session or stateless) can be active at a time")
		}
		if moduleName == string(types.StatelessModule) && hasSession {
			panic("goauth: cannot register stateless module: session module is already registered. Only one auth module (session or stateless) can be active at a time")
		}
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
		// Apply middlewares to route handler based on route's Middlewares attribute
		// This applies both global middlewares and route-specific middlewares
		handler := a.middlewareManager.ApplyWithRouteMiddlewares(route.Name, http.HandlerFunc(route.Handler), route.Middlewares)

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

	// Check if an auth module is registered, if not use stateless as default
	_, hasSession := a.modules[string(types.SessionModule)]
	_, hasStateless := a.modules[string(types.StatelessModule)]

	if !hasSession && !hasStateless {
		a.logger.Info("No auth module registered, using stateless as default")
		statelessModule := stateless.New(&config.StatelessModuleConfig{
			RefreshTokenRotation: true,
		}, nil)
		a.modules[statelessModule.Name()] = statelessModule
	}

	// Run migrations if enabled
	// Storage implementations handle their own models internally
	if a.config.AutoMigrate && a.storage != nil {
		a.logger.Info("Running auto-migrations")
		if err := a.storage.Migrate(ctx); err != nil {
			return fmt.Errorf("failed to run migrations: %w", err)
		}
	}

	// Initialize all modules
	for name, module := range a.modules {
		a.logger.Info("Initializing module", "name", name)
		if err := module.Init(ctx, a.moduleDependencies); err != nil {
			return fmt.Errorf("failed to initialize module %s: %w", name, err)
		}

		// Register module hooks
		if err := module.RegisterHooks(a.moduleDependencies.Events); err != nil {
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
	if !a.initialized {
		a.logger.Warn("RequireAuth called before initialization")
		return next
	}

	// Create auth middleware using core configuration and security manager
	mw := middlewares.NewAuthMiddleware(a.config, a.moduleDependencies.SecurityManager)
	return mw.AuthMiddleware(next)
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

// On allows users to subscribe to any event type
func (a *Auth) On(event types.EventType, handler types.EventHandler, opts ...interface{}) {
	a.moduleDependencies.Events.Subscribe(event, handler, opts...)
}

// asyncBackendAdapter adapts config.AsyncBackend to events.AsyncBackend
type asyncBackendAdapter struct {
	backend types.AsyncBackend
}

func (a *asyncBackendAdapter) Publish(ctx context.Context, eventType types.EventType, event *types.Event) error {
	return a.backend.Publish(ctx, eventType, event)
}

func (a *asyncBackendAdapter) Close() error {
	return a.backend.Close()
}

func (a *asyncBackendAdapter) Name() string {
	return a.backend.Name()
}
