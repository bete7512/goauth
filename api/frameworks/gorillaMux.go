package frameworks

// // GorillaMuxAdapter adapts the core authentication routes to the Gorilla Mux framework
// type GorillaMuxAdapter struct {
// 	handler *core.AuthHandler
// }

// // NewGorillaMuxAdapter creates a new Gorilla Mux adapter
// func NewGorillaMuxAdapter(handler *core.AuthHandler) *GorillaMuxAdapter {
// 	return &GorillaMuxAdapter{handler: handler}
// }

// // SetupRoutes registers all authentication routes with Gorilla Mux
// func (a *GorillaMuxAdapter) SetupRoutes(router interface{}) error {
// 	muxRouter, ok := router.(*mux.Router)
// 	if !ok {
// 		return &InvalidRouterError{Expected: "mux.Router", Got: router}
// 	}

// 	// Setup Swagger if enabled
// 	if a.handler.Auth.Config.App.Swagger.Enable {
// 		// TODO: Add Swagger setup for Gorilla Mux
// 	}

// 	// Get all routes
// 	allRoutes := a.handler.GetAllRoutes()

// 	// Create a sub-router for the auth base path
// 	authRouter := muxRouter.PathPrefix(a.handler.Auth.Config.App.BasePath).Subrouter()
// 	{
// 		for _, route := range allRoutes {
// 			// Build the middleware chain
// 			chainedHandler := a.handler.BuildChain(route.Name, http.HandlerFunc(route.Handler))

// 			// Adapt the http.Handler to Gorilla Mux
// 			muxHandler := a.adaptToMux(chainedHandler)

// 			// Register the route
// 			authRouter.HandleFunc(route.Path, muxHandler).Methods(route.Method)
// 		}
// 	}

// 	return nil
// }

// // GetMiddleware returns Gorilla Mux-specific middleware
// func (a *GorillaMuxAdapter) GetMiddleware() interface{} {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			// Global middleware for Gorilla Mux
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }

// // GetFrameworkType returns the framework type
// func (a *GorillaMuxAdapter) GetFrameworkType() core.FrameworkType {
// 	return core.FrameworkGorillaMux
// }

// // adaptToMux converts an http.Handler to a gorilla mux handler
// func (a *GorillaMuxAdapter) adaptToMux(h http.Handler) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		h.ServeHTTP(w, r)
// 	}
// }
