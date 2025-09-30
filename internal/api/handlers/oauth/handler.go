package oauth_handler

import (
	common_handler "github.com/bete7512/goauth/internal/api/handlers/common"
	"github.com/bete7512/goauth/internal/services"
	"github.com/bete7512/goauth/pkg/config"
)

type OAuthHandler struct {
	services *services.ServiceContainer
	common   *common_handler.Common
	config   *config.Auth
}

func NewOAuthHandler(services *services.ServiceContainer, common *common_handler.Common, config *config.Auth) *OAuthHandler {
	return &OAuthHandler{
		services: services,
		common:   common,
		config:   config,
	}
}
