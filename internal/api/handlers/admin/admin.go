package admin_handler

import (
	common_handler "github.com/bete7512/goauth/internal/api/handlers/common"
	"github.com/bete7512/goauth/internal/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/go-playground/validator/v10"
)

type AdminHandler struct {
	services  *services.ServiceContainer
	common    *common_handler.Common
	config    *config.Auth
	validator *validator.Validate
}

func NewAdminHandler(services *services.ServiceContainer, common *common_handler.Common, config *config.Auth) *AdminHandler {
	return &AdminHandler{
		services:  services,
		common:    common,
		config:    config,
		validator: validator.New(),
	}
}
