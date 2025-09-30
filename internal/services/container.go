package services

import (
	admin_service "github.com/bete7512/goauth/internal/services/admin"
	auth_service "github.com/bete7512/goauth/internal/services/auth"
	notification_service "github.com/bete7512/goauth/internal/services/notification"
	oauth_service "github.com/bete7512/goauth/internal/services/oauth"
	user_service "github.com/bete7512/goauth/internal/services/user"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type ServiceContainer struct {
	AuthService         interfaces.AuthService
	UserService         interfaces.UserService
	TwoFactorService    interfaces.TwoFactorService
	AdminService        interfaces.AdminService
	CSRFService         interfaces.CSRFService
	NotificationService interfaces.NotificationService
	OAuthService        interfaces.OAuthService
}

// NewServiceContainer creates a new service container with all dependencies
func NewServiceContainer(auth *config.Auth) *ServiceContainer {

	// Create services with proper dependency injection
	authService := auth_service.NewAuthService(
		auth.Repository.GetUserRepository(),
		auth.Repository.GetTokenRepository(),
		auth.Repository.GetSessionRepository(),
		auth.TokenManager,
		auth.Cache,
		auth.Logger,
		auth,
	)

	userService := user_service.NewUserService(
		auth.Repository.GetUserRepository(),
		auth.Repository.GetTokenRepository(),
		auth.Repository.GetSessionRepository(),
		auth.TokenManager,
		auth.Cache,
		auth.Logger,
		auth,
	)

	oauthService := oauth_service.NewOAuthService(
		auth.Repository.GetUserRepository(),
		auth.Repository.GetTokenRepository(),
		auth.TokenManager,
		auth.Repository.GetSessionRepository(),
		auth.Logger,
		auth,
	)

	notificationService := notification_service.NewNotificationService(
		auth.Email.CustomSender,
		auth.SMS.CustomSender,
		auth.Repository.GetTokenRepository(),
		auth.TokenManager,
		auth.Logger,
		auth,
	)

	adminService := admin_service.NewAdminService(
		auth.Repository.GetUserRepository(),
		auth.Repository.GetSessionRepository(),
		auth.Repository.GetTokenRepository(),
		auth.TokenManager,
		auth.Logger,
	)

	return &ServiceContainer{
		AuthService:         authService,
		UserService:         userService,
		OAuthService:        oauthService,
		NotificationService: notificationService,
		AdminService:        adminService,
	}
}
