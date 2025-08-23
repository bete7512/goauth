package dto

import "time"

// OAuthProvider represents the OAuth provider type
type OAuthProvider string

const (
	Google    OAuthProvider = "google"
	GitHub    OAuthProvider = "github"
	Facebook  OAuthProvider = "facebook"
	Apple     OAuthProvider = "apple"
	Twitter   OAuthProvider = "twitter"
	Discord   OAuthProvider = "discord"
	LinkedIn  OAuthProvider = "linkedin"
	Microsoft OAuthProvider = "microsoft"
)

// OAuthUserInfo represents user information from OAuth providers
type OAuthUserInfo struct {
	ProviderID    string        `json:"provider_id"`
	Email         string        `json:"email"`
	FirstName     string        `json:"first_name"`
	LastName      string        `json:"last_name"`
	Avatar        *string       `json:"avatar,omitempty"`
	Provider      OAuthProvider `json:"provider"`
	VerifiedEmail bool          `json:"verified_email"`
}

// OAuthSignInRequest represents OAuth sign-in request
type OAuthSignInRequest struct {
	Provider OAuthProvider `json:"provider" validate:"required"`
	State    string        `json:"state,omitempty"`
}

// OAuthCallbackRequest represents OAuth callback request
type OAuthCallbackRequest struct {
	Provider OAuthProvider `json:"provider" validate:"required"`
	Code     string        `json:"code" validate:"required"`
	State    string        `json:"state" validate:"required"`
}

// OAuthCallbackResponse represents OAuth callback response
type OAuthCallbackResponse struct {
	Message string     `json:"message"`
	User    *UserData  `json:"user,omitempty"`
	Tokens  *TokenData `json:"tokens,omitempty"`
}

// OAuthStateRequest represents OAuth state generation request
type OAuthStateRequest struct {
	Provider OAuthProvider `json:"provider" validate:"required"`
}

// OAuthStateResponse represents OAuth state generation response
type OAuthStateResponse struct {
	State string `json:"state"`
}

// OAuthProviderConfig represents OAuth provider configuration
type OAuthProviderConfig struct {
	Provider    OAuthProvider `json:"provider"`
	ClientID    string        `json:"client_id"`
	RedirectURL string        `json:"redirect_url"`
	Scopes      []string      `json:"scopes"`
	Enabled     bool          `json:"enabled"`
}

// OAuthProvidersResponse represents available OAuth providers
type OAuthProvidersResponse struct {
	Providers []OAuthProviderConfig `json:"providers"`
}

// OAuthUser represents OAuth user data
type OAuthUser struct {
	ID            string        `json:"id"`
	ProviderID    string        `json:"provider_id"`
	Email         string        `json:"email"`
	FirstName     string        `json:"first_name"`
	LastName      string        `json:"last_name"`
	Avatar        *string       `json:"avatar,omitempty"`
	Provider      OAuthProvider `json:"provider"`
	VerifiedEmail bool          `json:"verified_email"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

// OAuthLinkRequest represents OAuth account linking request
type OAuthLinkRequest struct {
	Provider OAuthProvider `json:"provider" validate:"required"`
	Code     string        `json:"code" validate:"required"`
	State    string        `json:"state" validate:"required"`
}

// OAuthUnlinkRequest represents OAuth account unlinking request
type OAuthUnlinkRequest struct {
	Provider OAuthProvider `json:"provider" validate:"required"`
}

// OAuthLinkResponse represents OAuth account linking response
type OAuthLinkResponse struct {
	Message string `json:"message"`
	Linked  bool   `json:"linked"`
}

// OAuthUserAccountsResponse represents user's linked OAuth accounts
type OAuthUserAccountsResponse struct {
	Accounts []OAuthUser `json:"accounts"`
}
