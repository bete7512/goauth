package goauth

import (
	"net/http"

	"github.com/bete7512/goauth/database"
	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/repositories"
	"github.com/bete7512/goauth/routes"
	"github.com/bete7512/goauth/routes/handlers"
	"github.com/bete7512/goauth/types"
	"github.com/gin-gonic/gin"
)

type AuthService struct {
	Config      types.Config
	Repository  interfaces.RepositoryFactory
	HookManager *hooks.HookManager
	// SwaggerDocs *docs.SwaggerDocs // Add Swagger docs
}

func NewAuth(conf types.Config) (*AuthService, error) {
	_, err := NewBuilder().WithConfig(conf).Build()
	if err != nil {
		return nil, err
	}
	dbClient, err := database.NewDBClient(conf.Database)
	if err != nil {
		return nil, err
	}

	if err := dbClient.Connect(); err != nil {
		return nil, err
	}

	repositoryFactory, err := repositories.NewRepositoryFactory(conf.Database.Type, dbClient.GetDB())
	if err != nil {
		return nil, err
	}

	// // Initialize Swagger docs if enabled
	// var swaggerDocs *docs.SwaggerDocs
	// if conf.Swagger.Enable {
	// 	swaggerDocs = docs.NewSwaggerDocs(conf)

	// 	// Set custom info if provided
	// 	if conf.Swagger.Title != "" {
	// 		docs.SwaggerInfo.Title = conf.Swagger.Title
	// 	}
	// 	if conf.Swagger.Description != "" {
	// 		docs.SwaggerInfo.Description = conf.Swagger.Description
	// 	}
	// 	if conf.Swagger.Version != "" {
	// 		docs.SwaggerInfo.Version = conf.Swagger.Version
	// 	}

	// 	// Initialize and save to file if output path is specified
	// 	if err := swaggerDocs.Initialize(); err != nil {
	// 		return nil, err
	// 	}

	// 	if conf.Swagger.OutputPath != "" {
	// 		if err := swaggerDocs.SaveToFile(conf.Swagger.OutputPath); err != nil {
	// 			return nil, err
	// 		}
	// 	}

	// 	// Register with swag for compatibility with swaggo/swag
	// 	swaggerDocs.RegisterSwag()
	// }

	return &AuthService{
		Config:      conf,
		Repository:  repositoryFactory,
		HookManager: hooks.NewHookManager(),
		// SwaggerDocs: swaggerDocs,
	}, nil
}

func (a *AuthService) RegisterBeforeHook(route string, hook hooks.RouteHook) {
	a.HookManager.RegisterBeforeHook(route, hook)
}

// RegisterAfterHook registers a function to be executed after a specific route
func (a *AuthService) RegisterAfterHook(route string, hook hooks.RouteHook) {
	a.HookManager.RegisterAfterHook(route, hook)
}

func (a *AuthService) ClearHooks(route string) {
	a.HookManager.Clear(route)
}

func (a *AuthService) ClearAllHooks() {
	a.HookManager.ClearAll()
}

func (a *AuthService) GetGinAuthMiddleware(r *gin.Engine) gin.HandlerFunc {
	ginHandler := routes.NewGinHandler(handlers.AuthHandler{
		Auth: &types.Auth{
			Config:      a.Config,
			Repository:  a.Repository,
			HookManager: a.HookManager,
		},
	})
	return ginHandler.GinMiddleWare(r)
}
func (a *AuthService) GetGinAuthRoutes(r *gin.Engine) {
	ginHandler := routes.NewGinHandler(handlers.AuthHandler{
		Auth: &types.Auth{
			Config:      a.Config,
			Repository:  a.Repository,
			HookManager: a.HookManager,
		},
	})
	ginHandler.SetupRoutes(r)

	// Set up Swagger UI if enabled
	// if a.Config.Swagger.Enable && a.SwaggerDocs != nil {
	// 	a.SwaggerDocs.SetupSwaggerRoutes(r)
	// }
}

func (a *AuthService) GetHttpAuthMiddleware(next http.Handler) http.Handler {
	httpHandler := routes.NewHttpHandler(handlers.AuthHandler{
		Auth: &types.Auth{
			Config:      a.Config,
			Repository:  a.Repository,
			HookManager: a.HookManager,
		},
	})
	return httpHandler.HttpMiddleWare(next)
}

func (a *AuthService) GetHttpAuthRoutes(s *http.ServeMux) {
	httpHandler := routes.NewHttpHandler(handlers.AuthHandler{
		Auth: &types.Auth{
			Config:      a.Config,
			Repository:  a.Repository,
			HookManager: a.HookManager,
		},
	})
	httpHandler.SetupRoutes(s)

	// Set up Swagger UI if enabled
	// if a.Config.Swagger.Enable && a.SwaggerDocs != nil {
	// 	a.SwaggerDocs.SetupHttpSwaggerRoutes(s)
	// }
}

