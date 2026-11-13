// Package dto holds the request and response shapes of the SAML module.
package dto

import "time"

// AuthResponse is returned by the ACS when no redirect URL is configured.
type AuthResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	ExpiresIn    int64    `json:"expires_in"`
	TokenType    string   `json:"token_type"`
	User         *UserDTO `json:"user"`
	IsNewUser    bool     `json:"is_new_user"`
	Provider     string   `json:"provider"`
}

// UserDTO is the user data returned in responses.
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

// ProviderInfo describes one configured SAML connection.
type ProviderInfo struct {
	Name        string `json:"name"`
	LoginURL    string `json:"login_url"`
	MetadataURL string `json:"metadata_url"`
}

// ProvidersResponse lists the configured SAML connections.
type ProvidersResponse struct {
	Providers []ProviderInfo `json:"providers"`
}
