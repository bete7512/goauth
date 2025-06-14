package goauth

import (
	"errors"
	"net/http"

	"github.com/bete7512/goauth/api"
	"github.com/bete7512/goauth/api/routes"
	"github.com/bete7512/goauth/database"
	"github.com/bete7512/goauth/hooks"
	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/logger"
	"github.com/bete7512/goauth/ratelimiter"
	"github.com/bete7512/goauth/recaptcha"
	"github.com/bete7512/goauth/repositories"
	tokenManager "github.com/bete7512/goauth/tokens"
	"github.com/bete7512/goauth/types"
	"github.com/gin-gonic/gin"
)

type AuthService struct {
	Config           types.Config
	Repository       interfaces.RepositoryFactory
	HookManager      *hooks.HookManager
	RateLimiter      types.RateLimiter
	RecaptchaManager types.CaptchaVerifier
	Logger           logger.Log
}

func NewAuth(conf types.Config) (*AuthService, error) {
	var repositoryFactory interfaces.RepositoryFactory
	var authService *AuthService
	var recaptchaVerifier types.CaptchaVerifier
	_, err := NewBuilder().WithConfig(conf).Build()
	if err != nil {
		return nil, err
	}
	if conf.EnableCustomStorageRepository {
		repositoryFactory = conf.StorageRepositoryFactory.Factory
		if repositoryFactory == nil {
			return nil, errors.New("repository factory is nil")
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

	if conf.EnableRecaptcha {
		if conf.RecaptchaConfig == nil {
			return nil, errors.New("recaptcha config is nil")
		}
		
		recaptchaVerifier = recaptcha.NewRecaptchaVerifier(*conf.RecaptchaConfig)
	}

	logger.New("info", logger.LogOptions{
		DisableAll:     false,
		DisableInfo:    false,
		DisableDebug:   false,
		DisableWarning: false,
	})

	loggerInstance := logger.Get()
	if loggerInstance == nil {
		return nil, errors.New("logger is not initialized")
	}
	authService = &AuthService{
		Config:           conf,
		Repository:       repositoryFactory,
		HookManager:      hooks.NewHookManager(),
		RateLimiter:      ratelimiter.NewRateLimiter(conf),
		RecaptchaManager: recaptchaVerifier,
		Logger:           loggerInstance,
	}

	return authService, nil
}

func (a *AuthService) RegisterBeforeHook(route string, hook hooks.RouteHook) error {
	return a.HookManager.RegisterBeforeHook(route, hook)
}

func (a *AuthService) RegisterAfterHook(route string, hook hooks.RouteHook) error {
	return a.HookManager.RegisterAfterHook(route, hook)
}

func (a *AuthService) GetGinAuthMiddleware(r *gin.Engine) gin.HandlerFunc {
	ginHandler := api.NewGinHandler(routes.AuthHandler{
		Auth: &types.Auth{
			Config:      a.Config,
			Repository:  a.Repository,
			HookManager: a.HookManager,
		},
	})
	return ginHandler.GinMiddleWare(r)
}
func (a *AuthService) GetGinAuthRoutes(r *gin.Engine) {
	ginHandler := api.NewGinHandler(routes.AuthHandler{
		Auth: &types.Auth{
			Config:       a.Config,
			Repository:   a.Repository,
			HookManager:  a.HookManager,
			TokenManager: tokenManager.NewTokenManager(a.Config),
			RateLimiter:  &a.RateLimiter,
		},
	})
	ginHandler.SetupRoutes(r)
}

func (a *AuthService) GetHttpAuthMiddleware(next http.Handler) http.Handler {
	httpHandler := api.NewHttpHandler(routes.AuthHandler{
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
	httpHandler := api.NewHttpHandler(routes.AuthHandler{
		Auth: &types.Auth{
			Config:       a.Config,
			Repository:   a.Repository,
			HookManager:  a.HookManager,
			TokenManager: tokenManager.NewTokenManager(a.Config),
		},
	})
	httpHandler.SetupRoutes(s)
}
