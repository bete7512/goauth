package docs

import (
	"log"

	doc_api "github.com/bete7512/goauth/api/docs/api"
	oauth "github.com/bete7512/goauth/api/docs/api/oauth"
	definitions "github.com/bete7512/goauth/api/docs/definations"
)

// SwaggerInfo contains information for generating Swagger documentation
type SwaggerInfo struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Host        string   `json:"host"`
	BasePath    string   `json:"basePath"`
	DocPath     string   `json:"docPath"`
	Schemes     []string `json:"schemes"`
}

// Default values for Swagger documentation
const (
	DefaultTitle       = "GoAuth API"
	DefaultDescription = "A comprehensive authentication and authorization API built with Go"
	DefaultVersion     = "1.0.0"
	DefaultHost        = "localhost:8080"
	DefaultBasePath    = "/api/v1"
	DefaultDocPath     = "/docs"
)

var DefaultSchemes = []string{"http", "https"}

// SwaggerDoc returns the complete Swagger documentation
func SwaggerDoc(info SwaggerInfo) map[string]interface{} {
	// Apply default values if fields are empty
	if info.Title == "" {
		info.Title = DefaultTitle
	}
	if info.Description == "" {
		info.Description = DefaultDescription
	}
	if info.Version == "" {
		info.Version = DefaultVersion
	}
	if info.Host == "" {
		info.Host = DefaultHost
	}
	if info.BasePath == "" {
		log.Println("BasePath is empty, setting to '/'")
		info.BasePath = DefaultBasePath
	}
	if info.DocPath == "" {
		log.Println("DocPath is empty, setting to '/docs'")
		info.DocPath = DefaultDocPath
	}
	if len(info.Schemes) == 0 {
		info.Schemes = DefaultSchemes
	}
	return map[string]interface{}{
		"swagger": "2.0",
		"info": map[string]interface{}{
			"title":       info.Title,
			"description": info.Description,
			"version":     info.Version,
		},
		"host":     info.Host,
		"basePath": "",
		"schemes":  info.Schemes,
		"paths":    Paths(info.BasePath),
		"definitions": map[string]interface{}{
			"User":                           definitions.UserDefinition(),
			"Error":                          definitions.ErrorDefinition(),
			"RegisterRequest":                definitions.RegisterRequestDefinition(),
			"LoginRequest":                   definitions.LoginRequestDefinition(),
			"RefreshTokenRequest":            definitions.RefreshTokenRequestDefinition(),
			"ForgotPasswordRequest":          definitions.ForgotPasswordRequestDefinition(),
			"ResetPasswordRequest":           definitions.ResetPasswordRequestDefinition(),
			"UpdateProfileRequest":           definitions.UpdateProfileRequestDefinition(),
			"ChangePasswordRequest":          definitions.ChangePasswordRequestDefinition(),
			"DeactivateUserRequest":          definitions.DeactivateUserRequestDefinition(),
			"VerifyTwoFactorRequest":         definitions.VerifyTwoFactorRequestDefinition(),
			"DisableTwoFactorRequest":        definitions.DisableTwoFactorRequestDefinition(),
			"VerifyEmailRequest":             definitions.VerifyEmailRequestDefinition(),
			"ResendVerificationEmailRequest": definitions.ResendVerificationEmailRequestDefinition(),
			"UserResponse":                   definitions.UserResponseDefinition(),
		},
		"securityDefinitions": map[string]interface{}{
			"BearerAuth": map[string]interface{}{
				"type":        "apiKey",
				"name":        "Authorization",
				"in":          "header",
				"description": "Enter your bearer token in the format **Bearer {token}**",
			},
		},
	}
}

// Paths returns all available API paths
func Paths(basePath string) map[string]interface{} {
	return map[string]interface{}{
		// // Authentication endpoints
		basePath + "/register":                  doc_api.RegisterPath(),
		basePath + "/login":                     doc_api.LoginPath(),
		basePath + "/logout":                    doc_api.LogoutPath(),
		basePath + "/refresh-token":             doc_api.RefreshTokenPath(),
		basePath + "/forgot-password":           doc_api.ForgotPasswordPath(),
		basePath + "/me":                        doc_api.GetMePath(),
		basePath + "/reset-password":            doc_api.ResetPasswordPath(),
		basePath + "/magic-link":                doc_api.MagicLinkPath(),
		basePath + "/magic-link/callback":       doc_api.MagicLinkCallbackPath(),
		basePath + "/update-profile":            doc_api.UpdateProfilePath(),
		basePath + "/deactivate-user":           doc_api.DeactivateUserPath(),
		basePath + "/enable-two-factor":         doc_api.EnableTwoFactorPath(),
		basePath + "/verify-two-factor":         doc_api.VerifyTwoFactorPath(),
		basePath + "/disable-two-factor":        doc_api.DisableTwoFactorPath(),
		basePath + "/verify-email":              doc_api.VerifyEmailPath(),
		basePath + "/resend-verification-email": doc_api.ResendVerificationEmailPath(),

		// OAuth endpoints
		basePath + "/oauth/google":             oauth.GoogleOAuthPath(),
		basePath + "/oauth/google/callback":    oauth.GoogleOAuthCallbackPath(),
		basePath + "/oauth/github":             oauth.GitHubOAuthPath(),
		basePath + "/oauth/github/callback":    oauth.GitHubOAuthCallbackPath(),
		basePath + "/oauth/facebook":           oauth.FacebookOAuthPath(),
		basePath + "/oauth/facebook/callback":  oauth.FacebookOAuthCallbackPath(),
		basePath + "/oauth/microsoft":          oauth.MicrosoftOAuthPath(),
		basePath + "/oauth/microsoft/callback": oauth.MicrosoftOAuthCallbackPath(),
		basePath + "/oauth/apple":              oauth.AppleOAuthPath(),
		basePath + "/oauth/apple/callback":     oauth.AppleOAuthCallbackPath(),
		basePath + "/oauth/discord":            oauth.DiscordOAuthPath(),
		basePath + "/oauth/discord/callback":   oauth.DiscordOAuthCallbackPath(),
	}
}
