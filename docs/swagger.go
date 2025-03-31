package docs

import (
	"log"

	doc_api "github.com/bete7512/goauth/docs/api"
	definitions "github.com/bete7512/goauth/docs/definations"
)

// SwaggerInfo holds the general API information
type SwaggerInfo struct {
	Version     string
	Host        string
	BasePath    string
	DocPath     string
	Title       string
	Description string
	Schemes     []string
}

// Default values for SwaggerInfo fields
const (
	DefaultTitle       = "Authentication API"
	DefaultDescription = "API endpoints for user authentication and management"
	DefaultVersion     = "1.0"
	DefaultHost        = "localhost:8080"
	DefaultBasePath    = "/"
	DefaultDocPath     = "/docs"
)

// DefaultSchemes provides default protocol schemes if none are specified
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
			"User":            definitions.UserDefinition(),
			"Error":           definitions.ErrorDefinition(),
			"RegisterRequest": definitions.RegisterRequestDefinition(),
			"LoginRequest":    definitions.LoginRequestDefinition(),
			"RefreshTokenRequest": definitions.RefreshTokenRequestDefinition(),
			"ForgotPasswordRequest": definitions.ForgotPasswordRequestDefinition(),
			"ResetPasswordRequest": definitions.ResetPasswordRequestDefinition(),
			"UpdateProfileRequest": definitions.UpdateProfileRequestDefinition(),
			"ChangePasswordRequest": definitions.ChangePasswordRequestDefinition(),
			"DeactivateUserRequest": definitions.DeactivateUserRequestDefinition(),
			"VerifyTwoFactorRequest": definitions.VerifyTwoFactorRequestDefinition(),
			"DisableTwoFactorRequest": definitions.DisableTwoFactorRequestDefinition(),
			"VerifyEmailRequest": definitions.VerifyEmailRequestDefinition(),
			"ResendVerificationEmailRequest": definitions.ResendVerificationEmailRequestDefinition(),
			"UserResponse": definitions.UserResponseDefinition(),
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
		basePath + "/register":        doc_api.RegisterPath(),
		basePath + "/login":           doc_api.LoginPath(),
		basePath + "/logout":          doc_api.LogoutPath(),
		basePath + "/refresh-token":   doc_api.RefreshTokenPath(),
		basePath + "/forgot-password": doc_api.ForgotPasswordPath(),
		basePath + "/reset-password":  doc_api.ResetPasswordPath(),
		// basePath + "/update-profile":            UpdateProfilePath(),
		// basePath + "/deactivate-user":           DeactivateUserPath(),
		// basePath + "/me":                        GetMePath(),
		// basePath + "/enable-two-factor":         EnableTwoFactorPath(),
		// basePath + "/verify-two-factor":         VerifyTwoFactorPath(),
		// basePath + "/disable-two-factor":        DisableTwoFactorPath(),
		// basePath + "/verify-email":              VerifyEmailPath(),
		// basePath + "/resend-verification-email": ResendVerificationEmailPath(),
		// basePath + "/oauth/google":              GoogleOAuthPath(),
		// basePath + "/oauth/google/callback":     GoogleOAuthCallbackPath(),
	}
}
