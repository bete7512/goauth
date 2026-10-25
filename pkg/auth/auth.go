package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bete7512/goauth/internal/authentication"
	"github.com/bete7512/goauth/internal/events"
	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/middleware"
	"github.com/bete7512/goauth/internal/modules/core"
	"github.com/bete7512/goauth/internal/modules/core/middlewares"
	"github.com/bete7512/goauth/internal/modules/ratelimit"
	"github.com/bete7512/goauth/internal/modules/stateless"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

type Auth struct {
	config             *config.Config
	storage            types.Storage
	modules            map[string]config.Module
	routes             []config.RouteInfo
	moduleDependencies config.ModuleDependencies
	eventBus           *events.EventBus
	middlewareManager  *middleware.Manager
	logger             types.Logger
	initialized        atomic.Bool
	lifecycleMu        sync.Mutex
	registryMu         sync.RWMutex
	configMu           sync.RWMutex
	closed             bool
	closeErr           error
	moduleOrder        []string
	startedModules     []config.Module
	cancel             context.CancelFunc
	outboxDone         chan struct{}
	requestSlots       chan struct{}
}

// New creates a new Auth instance
// Note: After creating Auth, you should call Use() to register auth modules:
//   - auth.Use(session.New(...)) for session-based authentication
//   - auth.Use(stateless.New(...)) for stateless JWT authentication
func New(cfg *config.Config) (*Auth, error) {
	if cfg == nil {
		return nil, config.ErrConfig("config is required")
	}
	cfg = cfg.Clone()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var securityManager types.SecurityManager = cfg.SecurityManager
	if securityManager == nil {
		manager := security.NewSecurityManager(cfg.Security)
		if err := manager.JWTKeyringError(); err != nil {
			return nil, fmt.Errorf("invalid JWT configuration: %w", err)
		}
		securityManager = manager
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

	// Note: CORS is NOT handled by GoAuth. Apply your own CORS middleware
	// at the framework level (e.g., wrap the mux, use gin-contrib/cors, etc.).
	// See examples/main.go for a reference implementation.

	// Add request ID middleware
	middlewareManager.Register(middleware.MiddlewareConfig{
		Name:       "auth.add-request-id",
		Middleware: middleware.RequestID(),
		Priority:   90,
		Global:     true,
	})

	auth := &Auth{requestSlots: make(chan struct{}, cfg.MaxConcurrentRequests),
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

	interceptorRegistry := interceptor.NewRegistry()

	eventBusAdapter := events.NewEventBusAdapter(eventBus)
	auth.moduleDependencies = config.ModuleDependencies{
		Storage:           cfg.Storage,
		Config:            cfg,
		Logger:            configLogger,
		Events:            eventBusAdapter,
		MiddlewareManager: middlewareManager,
		SecurityManager:   securityManager,
		AuthInterceptors:  interceptorRegistry,
	}

	// Auto-register core module if not already configured
	// Core module will get storage from deps.Storage.Core() during initialization
	{
		coreConfig := &config.CoreConfig{}

		if auth.config.Core != nil {
			*coreConfig = *auth.config.Core
		}

		// Pass nil for customStorage - core will get storage from deps.Storage.Core()
		coreModule := core.New(coreConfig)
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
// Registering both returns an error. If neither is registered, stateless
// is used as the default during Initialize().
func (a *Auth) Use(component config.Component) error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if component == nil || (reflect.ValueOf(component).Kind() == reflect.Ptr && reflect.ValueOf(component).IsNil()) {
		return fmt.Errorf("module is nil")
	}
	module := config.AdaptModule(component)
	if module.Name() == "" {
		return fmt.Errorf("module name is empty")
	}
	if a.initialized.Load() || a.closed {
		return fmt.Errorf("cannot add module after initialization")
	}

	if _, exists := a.modules[module.Name()]; exists {
		return fmt.Errorf("module already registered: %s", module.Name())
	}

	moduleName := module.Name()
	if moduleName == string(types.SessionModule) || moduleName == string(types.StatelessModule) {
		_, hasSession := a.modules[string(types.SessionModule)]
		_, hasStateless := a.modules[string(types.StatelessModule)]

		if moduleName == string(types.SessionModule) && hasStateless {
			return fmt.Errorf("cannot register session module: stateless module is already registered; only one auth module (session or stateless) can be active at a time")
		}
		if moduleName == string(types.StatelessModule) && hasSession {
			return fmt.Errorf("cannot register stateless module: session module is already registered; only one auth module (session or stateless) can be active at a time")
		}
	}

	a.registryMu.Lock()
	a.modules[module.Name()] = module
	a.registryMu.Unlock()
	a.logger.Info("Module registered", "name", module.Name())
	return nil
}

func (a *Auth) Config() *config.Config {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	return a.config.Clone()
}

// Routes returns all registered routes with middlewares applied
func (a *Auth) Routes() []config.RouteInfo {
	if !a.initialized.Load() {
		a.logger.Warn("Routes called before initialization")
		return nil
	}

	a.registryMu.RLock()
	defer a.registryMu.RUnlock()
	// Return routes with middlewares applied
	routesWithMiddleware := make([]config.RouteInfo, len(a.routes))
	for i, route := range a.routes {
		// Apply middlewares to route handler based on route's Middlewares attribute
		// This applies both global middlewares and route-specific middlewares
		handler := a.middlewareManager.ApplyWithRouteMiddlewares(route.Name, http.HandlerFunc(route.Handler), route.Middlewares)
		guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.initialized.Load() {
				http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
				return
			}
			release, err := a.acquire(r.Context(), route.Name)
			if err != nil {
				http.Error(w, "authentication capacity exceeded", http.StatusServiceUnavailable)
				return
			}
			defer release()
			start := time.Now()
			if a.config.Observer != nil {
				observed := &observedResponse{ResponseWriter: w}
				w = observed
				defer func() {
					a.config.Observer.ObserveOperation(r.Context(), route.Name, time.Since(start), observed.status > 0 && observed.status < 400)
				}()
			}
			r.Body = http.MaxBytesReader(w, r.Body, a.config.MaxRequestBodyBytes)
			r = r.WithContext(context.WithValue(r.Context(), types.RouteNameKey, route.Name))
			handler.ServeHTTP(w, r)
		})

		routesWithMiddleware[i] = config.RouteInfo{
			Name:    route.Name,
			Path:    route.Path,
			Method:  route.Method,
			Handler: guarded,
		}
	}

	return routesWithMiddleware
}

// Initialize initializes all modules and runs migrations
func (a *Auth) Initialize(ctx context.Context) (initErr error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.closed {
		return fmt.Errorf("auth is closed")
	}
	if a.initialized.Load() {
		return fmt.Errorf("auth already initialized")
	}
	ctx, a.cancel = context.WithCancel(ctx)
	defer func() {
		if initErr != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			initErr = errors.Join(initErr, a.shutdown(cleanupCtx))
		}
	}()

	// Check if an auth module is registered, if not use stateless as default
	_, hasSession := a.modules[string(types.SessionModule)]
	_, hasStateless := a.modules[string(types.StatelessModule)]

	if !hasSession && !hasStateless {
		a.logger.Info("No auth module registered, using stateless as default")
		statelessModule := stateless.New(&config.StatelessModuleConfig{
			RefreshTokenRotation: true,
		})
		a.registryMu.Lock()
		a.modules[statelessModule.Name()] = statelessModule
		a.registryMu.Unlock()
	}
	if _, hasRateLimit := a.modules[string(types.RateLimitModule)]; !hasRateLimit && (a.config.RateLimit == nil || !a.config.RateLimit.Disabled) {
		a.logger.Info("No rate limit module registered, using default rate limiter")
		rateLimitModule := ratelimit.New(a.config.RateLimit)
		a.registryMu.Lock()
		a.modules[rateLimitModule.Name()] = rateLimitModule
		a.registryMu.Unlock()
	}
	a.configMu.Lock()
	if hasSession {
		a.config.Security.AuthStrategy = types.StrategySession
	} else {
		a.config.Security.AuthStrategy = types.StrategyStateless
	}
	a.configMu.Unlock()
	var err error
	a.moduleOrder, err = a.modulePlan()
	if err != nil {
		return err
	}
	a.configMu.Lock()
	storageErr := a.resolveStorage()
	a.configMu.Unlock()
	if storageErr != nil {
		return storageErr
	}
	if a.config.DurableEvents {
		if _, ok := a.config.Storage.(types.TransactionalStorage); !ok {
			return fmt.Errorf("durable events require transactional storage")
		}
		if _, ok := a.config.Storage.(types.OutboxStore); !ok {
			return fmt.Errorf("durable events require outbox storage")
		}
	}
	engine := &authentication.Engine{Store: a.config.Storage, Config: a.config, Security: a.moduleDependencies.SecurityManager, Interceptors: a.moduleDependencies.AuthInterceptors, Tokens: a.config.Storage.Core().Tokens()}
	if a.config.Storage.Session() != nil {
		engine.Sessions = a.config.Storage.Session().Sessions()
	}
	a.moduleDependencies.Completion = engine

	// Run migrations
	if a.config.Migration.Auto {
		if err := a.ApplyMigrations(ctx); err != nil {
			return fmt.Errorf("apply migrations: %w", err)
		}
	}
	if a.config.Migration.OutputDir != "" {
		files, err := a.GenerateMigrationFiles(ctx, a.config.Migration.OutputDir)
		if err != nil {
			return fmt.Errorf("generate migration files: %w", err)
		}
		if len(files) > 0 {
			a.logger.Info("Migration files written", "up", files[0], "down", files[1])
		}
	}

	// Initialize all modules
	for _, name := range a.moduleOrder {
		module := a.modules[name]
		a.startedModules = append(a.startedModules, module)
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

	a.routes = a.buildRoutes()
	if err := a.validateRoutes(); err != nil {
		return err
	}

	// Start the event bus — registers the dispatcher with the async backend
	// and begins consuming events. Must happen after all hooks are registered
	// so that durable backends (NATS, Redis) replay messages to registered handlers.
	if err := a.eventBus.Start(ctx); err != nil {
		return fmt.Errorf("failed to start event bus: %w", err)
	}

	// Build routes
	if a.config.DurableEvents {
		a.outboxDone = make(chan struct{})
		go func() {
			defer close(a.outboxDone)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := a.eventBus.DrainOutbox(ctx, a.config.Storage.(types.OutboxStore)); err != nil && ctx.Err() == nil {
						a.logger.Error("outbox delivery failed", "error", err)
					}
				}
			}
		}()
	}
	a.initialized.Store(true)
	a.logger.Info("Auth initialization completed", "modules", len(a.modules), "routes", len(a.routes))
	return nil
}

// buildRoutes collects and processes routes from all modules
func (a *Auth) buildRoutes() []config.RouteInfo {
	var routes []config.RouteInfo
	for _, name := range a.moduleOrder {
		module := a.modules[name]
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
		if !a.initialized.Load() {
			http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		mw := middlewares.NewAuthMiddleware(a.config, a.moduleDependencies.SecurityManager)
		mw.AuthMiddleware(next).ServeHTTP(w, r)
	})
}

// GetModule retrieves a registered module by name
func (a *Auth) GetModule(name string) (config.Module, error) {
	a.registryMu.RLock()
	defer a.registryMu.RUnlock()
	module, exists := a.modules[name]
	if !exists {
		return nil, config.ErrConfig("module not found")
	}
	return module, nil
}

// Close gracefully shuts down the auth system
// Closes event bus, async backend, and storage connections
func (a *Auth) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return a.Shutdown(ctx)
}

// Shutdown stops accepting authentication, stops modules in reverse dependency
// order, and attempts every cleanup even if an earlier resource fails.
func (a *Auth) Shutdown(ctx context.Context) error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	return a.shutdown(ctx)
}

func (a *Auth) shutdown(ctx context.Context) error {
	if a.closed {
		return a.closeErr
	}
	a.closed = true
	a.initialized.Store(false)
	if a.cancel != nil {
		a.cancel()
	}
	var errs []error
	if a.outboxDone != nil {
		select {
		case <-a.outboxDone:
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
		}
	}
	for i := len(a.startedModules) - 1; i >= 0; i-- {
		if m, ok := a.startedModules[i].(config.ModuleShutdown); ok {
			if err := m.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Errorf("shutdown %s: %w", a.startedModules[i].Name(), err))
			}
		}
	}
	if a.eventBus != nil {
		errs = append(errs, a.eventBus.Shutdown(ctx))
	}
	if a.storage != nil && !a.config.BorrowStorage {
		errs = append(errs, a.storage.Close())
	}
	a.closeErr = errors.Join(errs...)
	return a.closeErr
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

func (a *asyncBackendAdapter) Subscribe(ctx context.Context, dispatcher types.EventDispatcher) error {
	return a.backend.Subscribe(ctx, dispatcher)
}

func (a *asyncBackendAdapter) Close() error {
	return a.backend.Close()
}

func (a *asyncBackendAdapter) Name() string {
	return a.backend.Name()
}

func (a *asyncBackendAdapter) Shutdown(ctx context.Context) error {
	if backend, ok := a.backend.(interface{ Shutdown(context.Context) error }); ok {
		return backend.Shutdown(ctx)
	}
	return a.backend.Close()
}

func (a *asyncBackendAdapter) SubscribeAcknowledged(ctx context.Context, dispatch func(context.Context, *types.Event) error) error {
	if backend, ok := a.backend.(types.AcknowledgingBackend); ok {
		return backend.SubscribeAcknowledged(ctx, dispatch)
	}
	return a.backend.Subscribe(ctx, func(ctx context.Context, event *types.Event) { _ = dispatch(ctx, event) })
}
