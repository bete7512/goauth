package auth_handler

import (
	common_handler "github.com/bete7512/goauth/internal/api/handlers/common"
	"github.com/bete7512/goauth/internal/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/go-playground/validator/v10"
)

type AuthHandler struct {
	services  *services.ServiceContainer
	common    *common_handler.Common
	config    *config.Auth
	validator *validator.Validate
}

func NewAuthHandler(services *services.ServiceContainer, common *common_handler.Common, config *config.Auth) *AuthHandler {
	return &AuthHandler{
		services:  services,
		common:    common,
		config:    config,
		validator: validator.New(),
	}
}
