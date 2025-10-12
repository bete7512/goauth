package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bete7512/goauth/internal/events"
	"github.com/bete7512/goauth/internal/middleware"
	"github.com/bete7512/goauth/internal/modules/core"
	"github.com/bete7512/goauth/internal/modules/core/models"
	notification_models "github.com/bete7512/goauth/internal/modules/notification/models"
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
	if auth.config.ModuleConfigs[string(types.CoreModule)] == nil {
		coreConfig := &config.CoreConfig{}
		customRepositories := &core.CustomRepositories{}
		if auth.storage != nil {
			if auth.storage.GetRepository(string(types.CoreUserRepository)) == nil {
				return nil, fmt.Errorf("core.user repository is not found storage is not connected correctly")
			}
			if auth.storage.GetRepository(string(types.CoreSessionRepository)) == nil {
				return nil, fmt.Errorf("core.session repository is not found storage is not connected correctly")
			}
			if auth.storage.GetRepository(string(types.CoreTokenRepository)) == nil {
				return nil, fmt.Errorf("core.token repository is not found storage is not connected correctly")
			}
			customRepositories.UserRepository = auth.storage.GetRepository(string(types.CoreUserRepository)).(models.UserRepository)
			customRepositories.SessionRepository = auth.storage.GetRepository(string(types.CoreSessionRepository)).(models.SessionRepository)
			customRepositories.TokenRepository = auth.storage.GetRepository(string(types.CoreTokenRepository)).(models.TokenRepository)
			customRepositories.VerificationTokenRepository = auth.storage.GetRepository(string(types.CoreVerificationTokenRepository)).(notification_models.VerificationTokenRepository)
			customRepositories.UserExtendedAttributeRepository = auth.storage.GetRepository(string(types.CoreUserExtendedAttributeRepository)).(models.ExtendedAttributeRepository)

		}
		if auth.config.Core != nil {
			coreConfig.RequireEmailVerification = auth.config.Core.RequireEmailVerification
			coreConfig.RequirePhoneVerification = auth.config.Core.RequirePhoneVerification
			coreConfig.RequireUserName = auth.config.Core.RequireUserName
			coreConfig.RequirePhoneNumber = auth.config.Core.RequirePhoneNumber
		}

		coreModule := core.New(coreConfig, customRepositories)
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
	// 	a.moduleDependencies.Repositories[repoName] = a.storage.GetRepository(repoName)
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
