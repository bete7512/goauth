package dto

import "time"

// AuthResponse is the response returned after successful OAuth authentication
type AuthResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	ExpiresIn    int64    `json:"expires_in"`
	TokenType    string   `json:"token_type"`
	User         *UserDTO `json:"user"`
	IsNewUser    bool     `json:"is_new_user"`
	Provider     string   `json:"provider"`
}

// UserDTO is the user data returned in responses
type UserDTO struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Username      string     `json:"username,omitempty"`
	Name          string     `json:"name,omitempty"`
	FirstName     string     `json:"first_name,omitempty"`
	LastName      string     `json:"last_name,omitempty"`
	Avatar        string     `json:"avatar,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	Active        bool       `json:"active"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
}

// ProviderInfo represents basic information about an OAuth provider
type ProviderInfo struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// ProvidersResponse is the response for listing available OAuth providers
type ProvidersResponse struct {
	Providers []ProviderInfo `json:"providers"`
}

// LinkedProvidersResponse is the response for listing a user's linked OAuth providers
type LinkedProvidersResponse struct {
	Providers []string `json:"providers"`
}

// ErrorResponse is the error response format
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
