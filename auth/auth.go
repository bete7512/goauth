// auth/auth.go
package goauth

import (
	"errors"
	"net/http"

	"github.com/bete7512/go-auth/auth/database"
	"github.com/bete7512/go-auth/auth/hooks"
	"github.com/bete7512/go-auth/auth/interfaces"
	"github.com/bete7512/go-auth/auth/repositories"
	"github.com/bete7512/go-auth/auth/routes"
	"github.com/bete7512/go-auth/auth/routes/handlers"
	types "github.com/bete7512/go-auth/auth/types"
	"github.com/gin-gonic/gin"
)

type AuthService struct {
	Config      types.Config
	Repository  interfaces.RepositoryFactory
	HookManager *hooks.HookManager
}

func NewAuth(conf types.Config) (*AuthService, error) {
	if conf.Database.URL == "" {
		return nil, errors.New("database is required")
	}
	if conf.JWTSecret == "" {
		return nil, errors.New("jwt secret is required")
	}
	if conf.Server.Type == "" {
		return nil, errors.New("server type is required")
	}
	if conf.Database.Type == "" {
		return nil, errors.New("database type is required")
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
	return &AuthService{
		Config:      conf,
		Repository:  repositoryFactory,
		HookManager: hooks.NewHookManager(),
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

func (a *AuthService) GetGinAuthRoutes(r *gin.Engine) {
	ginHandler := routes.NewGinHandler(handlers.AuthHandler{
		Auth: &types.Auth{
			Config:      a.Config,
			Repository:  a.Repository,
			HookManager: a.HookManager,
		},
	})
	ginHandler.SetupRoutes(r)
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

func (a *AuthService) GetHttpAuthRoutes(s *http.ServeMux) {
	httpHandler := routes.NewHttpHandler(handlers.AuthHandler{
		Auth: &types.Auth{
			Config:      a.Config,
			Repository:  a.Repository,
			HookManager: a.HookManager,
		},
	})
	httpHandler.SetupRoutes(s)
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


//TODO: continue doing for other go web frameworks
