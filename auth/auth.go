// auth/auth.go
package auth

import (
	"errors"

	"github.com/bete7512/go-auth/auth/database"
	"github.com/bete7512/go-auth/auth/interfaces"
	"github.com/bete7512/go-auth/auth/repositories"
	ginroutes "github.com/bete7512/go-auth/auth/routes/ginRoutes"
	types "github.com/bete7512/go-auth/auth/types"
	"github.com/gin-gonic/gin"
)

type AuthService struct {
	Config     types.Config
	Repository interfaces.RepositoryFactory
}

func NewAuth(conf types.Config) (*AuthService, error) {
	if conf.Database.URL == "" {
		return nil, errors.New("database is required")
	}
	if conf.JWTSecret == "" {
		return nil, errors.New("JWT secret is required")
	}
	if conf.Server.Type == "" {
		return nil, errors.New("server type is required")
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
		Config:     conf,
		Repository: repositoryFactory,
	}, nil
}

func (a *AuthService) GinAuthRoutes(r *gin.Engine) {
	ginHandler := ginroutes.NewGinHandler(&types.Auth{Config: a.Config, Repository: a.Repository})
	ginHandler.SetupRoutes(r)
}

func (a *AuthService) HttpAuthRoutes() {
	// Implementation for HTTP routes
}
