package services

import (
	"github.com/bete7512/goauth/internal/oauthproto"
	"github.com/bete7512/goauth/pkg/models"
)

// The scopes the module understands (OpenID Connect Core section 5.4).
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopePhone         = "phone"
	ScopeOfflineAccess = oauthproto.ScopeOfflineAccess
)

// supportedScopes lists every scope a client can be registered for, in the
// order they are advertised.
var supportedScopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopePhone, ScopeOfflineAccess}

// defaultClientScopes is what a client may request when its registration
// names no scopes.
var defaultClientScopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail}

// scopeDescriptions is what a consent page tells the user about a scope.
var scopeDescriptions = map[string]string{
	ScopeOpenID:        "Confirm who you are",
	ScopeProfile:       "See your name, username and profile picture",
	ScopeEmail:         "See your email address",
	ScopePhone:         "See your phone number",
	ScopeOfflineAccess: "Keep reading this information until you disconnect the application",
}

// supportedClaims lists the claims the module can release, for the discovery
// document.
var supportedClaims = []string{
	"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "at_hash",
	"name", "given_name", "family_name", "preferred_username", "picture", "updated_at",
	"email", "email_verified", "phone_number", "phone_number_verified",
}

// reservedClaims are set by the module and cannot be replaced by the host's
// claims function.
var reservedClaims = map[string]bool{
	"sub": true, "iss": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true,
	"auth_time": true, "nonce": true, "amr": true, "acr": true, "azp": true, "at_hash": true, "c_hash": true,
}

func supportedScope(name string) bool {
	for _, scope := range supportedScopes {
		if scope == name {
			return true
		}
	}
	return false
}

func hasScope(scopes []string, name string) bool {
	for _, scope := range scopes {
		if scope == name {
			return true
		}
	}
	return false
}

// userClaims returns the claims about user that scopes release (OpenID
// Connect Core section 5.4). Empty values are left out.
func userClaims(user *models.User, scopes []string) map[string]interface{} {
	claims := map[string]interface{}{}
	set := func(name, value string) {
		if value != "" {
			claims[name] = value
		}
	}
	if hasScope(scopes, ScopeProfile) {
		set("name", user.Name)
		set("given_name", user.FirstName)
		set("family_name", user.LastName)
		set("preferred_username", user.Username)
		set("picture", user.Avatar)
		updated := user.CreatedAt
		if user.UpdatedAt != nil && !user.UpdatedAt.IsZero() {
			updated = *user.UpdatedAt
		}
		if !updated.IsZero() {
			claims["updated_at"] = updated.Unix()
		}
	}
	if hasScope(scopes, ScopeEmail) && user.Email != "" {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}
	if hasScope(scopes, ScopePhone) && user.PhoneNumber != "" {
		claims["phone_number"] = user.PhoneNumber
		claims["phone_number_verified"] = user.PhoneNumberVerified
	}
	return claims
}
