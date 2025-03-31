package goauth

import (
	"errors"
	"log"
	"net/http"

	"github.com/bete7512/goauth/database"
	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/repositories"
	"github.com/bete7512/goauth/routes"
	"github.com/bete7512/goauth/routes/handlers"
	tokenManager "github.com/bete7512/goauth/tokens"
	"github.com/bete7512/goauth/types"
	"github.com/gin-gonic/gin"
)

type AuthService struct {
	Config      types.Config
	Repository  interfaces.RepositoryFactory
	HookManager *hooks.HookManager
}

func NewAuth(conf types.Config) (*AuthService, error) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var repositoryFactory interfaces.RepositoryFactory
	_, err := NewBuilder().WithConfig(conf).Build()
	if err != nil {
		return nil, err
	}
	if conf.DataAccessConfig.EnableDataAccess {
		repositoryFactory = conf.DataAccessConfig.Factory
		if repositoryFactory == nil {
			return nil, errors.New("repository factory is nil")
		}
		if err != nil {
			return nil, err
		}
	} else {
		dbClient, err := database.NewDBClient(conf.Database)
		if err != nil {
			return nil, err
		}
		if err := dbClient.Connect(); err != nil {
			return nil, err
		}
		repositoryFactory, err = repositories.NewRepositoryFactory(conf.Database.Type, dbClient.GetDB())
		if err != nil {
			return nil, err
		}
	}
	return &AuthService{
		Config:      conf,
		Repository:  repositoryFactory,
		HookManager: hooks.NewHookManager(),
	}, nil
}

func (a *AuthService) RegisterBeforeHook(route string, hook hooks.RouteHook) error {
	return a.HookManager.RegisterBeforeHook(route, hook)
}

func (a *AuthService) RegisterAfterHook(route string, hook hooks.RouteHook) error {
	return a.HookManager.RegisterAfterHook(route, hook)
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
			Config:       a.Config,
			Repository:   a.Repository,
			HookManager:  a.HookManager,
			TokenManager: tokenManager.NewTokenManager(a.Config),
		},
	})
	ginHandler.SetupRoutes(r)
}

func (a *AuthService) GetGinRoutesRaw(r *gin.Engine) handlers.AuthHandler {
	authHandler := handlers.AuthHandler{
		Auth: &types.Auth{
			Config:       a.Config,
			Repository:   a.Repository,
			HookManager:  a.HookManager,
			TokenManager: tokenManager.NewTokenManager(a.Config),
		},
	}
	routes.NewGinHandler(authHandler)
	return authHandler
}

func (a *AuthService) GetHttpAuthMiddleware(next http.Handler) http.Handler {
	httpHandler := routes.NewHttpHandler(handlers.AuthHandler{
		Auth: &types.Auth{
			Config:       a.Config,
			Repository:   a.Repository,
			HookManager:  a.HookManager,
			TokenManager: tokenManager.NewTokenManager(a.Config),
		},
	})
	return httpHandler.HttpMiddleWare(next)
}

func (a *AuthService) GetHttpAuthRoutes(s *http.ServeMux) {
	httpHandler := routes.NewHttpHandler(handlers.AuthHandler{
		Auth: &types.Auth{
			Config:       a.Config,
			Repository:   a.Repository,
			HookManager:  a.HookManager,
			TokenManager: tokenManager.NewTokenManager(a.Config),
		},
	})
	httpHandler.SetupRoutes(s)
}
