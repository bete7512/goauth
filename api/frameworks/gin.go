package frameworks

// // GinAdapter adapts the core authentication routes to the Gin framework
// type GinAdapter struct {
// 	handler *core.AuthHandler
// }

// // NewGinAdapter creates a new Gin adapter
// func NewGinAdapter(handler *core.AuthHandler) *GinAdapter {
// 	return &GinAdapter{handler: handler}
// }

// // SetupRoutes registers all authentication routes with Gin
// func (a *GinAdapter) SetupRoutes(router interface{}) error {
// 	ginEngine, ok := router.(*gin.Engine)
// 	if !ok {
// 		return &InvalidRouterError{Expected: "gin.Engine", Got: router}
// 	}

// 	// Setup Swagger if enabled
// 	if a.handler.Auth.Config.App.Swagger.Enable {
// 		docs.RegisterGinRoutes(ginEngine, docs.SwaggerInfo{
// 			Title:       a.handler.Auth.Config.App.Swagger.Title,
// 			Description: a.handler.Auth.Config.App.Swagger.Description,
// 			Version:     a.handler.Auth.Config.App.Swagger.Version,
// 			Host:        a.handler.Auth.Config.App.Swagger.Host,
// 			BasePath:    a.handler.Auth.Config.App.BasePath,
// 			DocPath:     a.handler.Auth.Config.App.Swagger.DocPath,
// 			Schemes:     []string{"http", "https"},
// 		})
// 	}

// 	// Get all routes
// 	allRoutes := a.handler.GetAllRoutes()

// 	// Create a group for the auth base path
// 	authGroup := ginEngine.Group(a.handler.Auth.Config.App.BasePath)
// 	{
// 		for _, route := range allRoutes {
// 			// Build the middleware chain
// 			chainedHandler := a.handler.BuildChain(route.Name, http.HandlerFunc(route.Handler))

// 			// Adapt the http.Handler to Gin
// 			ginHandler := a.adaptToGin(chainedHandler)

// 			// Register the route
// 			authGroup.Handle(route.Method, route.Path, ginHandler)
// 		}
// 	}

// 	return nil
// }

// // GetMiddleware returns Gin-specific middleware
// func (a *GinAdapter) GetMiddleware() interface{} {
// 	return func(c *gin.Context) {
// 		// Global middleware for Gin
// 		c.Next()
// 	}
// }

// // GetFrameworkType returns the framework type
// func (a *GinAdapter) GetFrameworkType() core.FrameworkType {
// 	return core.FrameworkGin
// }

// // adaptToGin converts an http.Handler to a gin.HandlerFunc
// func (a *GinAdapter) adaptToGin(h http.Handler) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		h.ServeHTTP(c.Writer, c.Request)
// 	}
// }

// // InvalidRouterError represents an error when the wrong router type is provided
// type InvalidRouterError struct {
// 	Expected string
// 	Got      interface{}
// }

// func (e *InvalidRouterError) Error() string {
// 	return "invalid router type: expected " + e.Expected + ", got " + string(rune(0))
// }
