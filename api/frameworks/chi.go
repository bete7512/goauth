package frameworks

// // ChiAdapter adapts the core authentication routes to the Chi framework
// type ChiAdapter struct {
// 	handler *core.AuthHandler
// }

// // NewChiAdapter creates a new Chi adapter
// func NewChiAdapter(handler *core.AuthHandler) *ChiAdapter {
// 	return &ChiAdapter{handler: handler}
// }

// // SetupRoutes registers all authentication routes with Chi
// func (a *ChiAdapter) SetupRoutes(router interface{}) error {
// 	chiRouter, ok := router.(chi.Router)
// 	if !ok {
// 		return &InvalidRouterError{Expected: "chi.Router", Got: router}
// 	}

// 	// Setup Swagger if enabled
// 	if a.handler.Auth.Config.App.Swagger.Enable {
// 		// TODO: Add Swagger setup for Chi
// 	}

// 	// Get all routes
// 	allRoutes := a.handler.GetAllRoutes()

// 	// Create a sub-router for the auth base path
// 	chiRouter.Route(a.handler.Auth.Config.App.BasePath, func(r chi.Router) {
// 		for _, route := range allRoutes {
// 			// Build the middleware chain
// 			chainedHandler := a.handler.BuildChain(route.Name, http.HandlerFunc(route.Handler))

// 			// Adapt the http.Handler to Chi
// 			chiHandler := a.adaptToChi(chainedHandler)

// 			// Register the route
// 			r.Method(route.Method, route.Path, chiHandler)
// 		}
// 	})

// 	return nil
// }

// // GetMiddleware returns Chi-specific middleware
// func (a *ChiAdapter) GetMiddleware() interface{} {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			// Global middleware for Chi
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }

// // GetFrameworkType returns the framework type
// func (a *ChiAdapter) GetFrameworkType() core.FrameworkType {
// 	return core.FrameworkChi
// }

// // adaptToChi converts an http.Handler to a chi.HandlerFunc
// func (a *ChiAdapter) adaptToChi(h http.Handler) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		h.ServeHTTP(w, r)
// 	}
// }
