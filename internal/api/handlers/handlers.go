package handlers

import (
	admin_handler "github.com/bete7512/goauth/internal/api/handlers/admin"
	auth_handler "github.com/bete7512/goauth/internal/api/handlers/auth"
	common_handler "github.com/bete7512/goauth/internal/api/handlers/common"
	oauth_handler "github.com/bete7512/goauth/internal/api/handlers/oauth"
	twofactor_handler "github.com/bete7512/goauth/internal/api/handlers/twofactor"
	user_handler "github.com/bete7512/goauth/internal/api/handlers/user"
	"github.com/bete7512/goauth/internal/services"
	"github.com/bete7512/goauth/pkg/config"
)

type AuthHandler struct {
	services  *services.ServiceContainer
	Admin     *admin_handler.AdminHandler
	Auth      *auth_handler.AuthHandler
	TwoFactor *twofactor_handler.TwoFactorHandler
	common    *common_handler.Common
	Oauth     *oauth_handler.OAuthHandler
	User      *user_handler.UserHandler
}

func NewAuthHandler(services *services.ServiceContainer, config *config.Auth) *AuthHandler {
	return &AuthHandler{
		services:  services,
		Auth:      auth_handler.NewAuthHandler(services, common_handler.NewCommon(config), config),
		common:    common_handler.NewCommon(config),
		Admin:     admin_handler.NewAdminHandler(services, common_handler.NewCommon(config), config),
		TwoFactor: twofactor_handler.NewTwoFactorHandler(services, common_handler.NewCommon(config), config),
		Oauth:     oauth_handler.NewOAuthHandler(services, common_handler.NewCommon(config), config),
		User:      user_handler.NewUserHandler(services, common_handler.NewCommon(config), config),
	}
}
