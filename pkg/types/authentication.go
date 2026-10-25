package types

import (
	"context"
	"github.com/bete7512/goauth/pkg/models"
	"time"
)

// AuthenticationStatus is the outcome of completing an authentication.
type AuthenticationStatus string

// Authentication outcomes.
const (
	Authenticated     AuthenticationStatus = "authenticated"
	ChallengeRequired AuthenticationStatus = "challenge_required"
	Denied            AuthenticationStatus = "denied"
)

// AuthenticationEvidence is submitted only by trusted in-process authenticators
// after verifying a credential. It must never be populated from an HTTP body.
type AuthenticationEvidence struct {
	AuthenticatedAt time.Time
	Methods         []string
	User            *models.User
	Method          string
	Phase           AuthPhase
	Metadata        *RequestMetadata
	Claims          map[string]interface{}
}

// AuthenticationResult is transport independent. HTTP adapters retain their
// existing response envelopes while sharing this completion contract.
type AuthenticationResult struct {
	UserID       string
	Status       AuthenticationStatus
	AccessToken  string
	RefreshToken string
	SessionID    string
	ExpiresIn    int64
	Challenges   []LoginChallenge
	Data         map[string]interface{}
}

// SignInRequest is independent of HTTP and handler DTOs.
type SignInRequest struct {
	Email    string
	Username string
	Password string
	Metadata *RequestMetadata
}

// PasswordAuthenticator signs a user in with a password, outside HTTP. Auth
// implements it through SignIn.
type PasswordAuthenticator interface {
	SignIn(context.Context, SignInRequest) (AuthenticationResult, error)
}

// GrantContext persists assurance and selected organization across refreshes.
// Authorization still checks current membership in storage.
type GrantContext struct {
	AuthenticatedAt time.Time `json:"authenticated_at"`
	Methods         []string  `json:"methods"`
	TokenVersion    int       `json:"token_version"`
	OrganizationID  string    `json:"organization_id,omitempty"`
}

// AuthenticationCompleter turns verified evidence into credentials or a
// challenge. Modules receive it as ModuleDependencies.Completion.
type AuthenticationCompleter interface {
	Complete(context.Context, AuthenticationEvidence) (AuthenticationResult, *GoAuthError)
}

// AuthenticationTransaction is persisted under a purpose-bound continuation.
// Each transition replaces or consumes the expected live record atomically.
type AuthenticationTransaction struct {
	Version         int                    `json:"version"`
	RealmID         string                 `json:"realm_id"`
	UserID          string                 `json:"user_id"`
	TokenVersion    int                    `json:"token_version"`
	AuthenticatedAt time.Time              `json:"authenticated_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
	Methods         []string               `json:"methods"`
	Required        []LoginChallengeType   `json:"required"`
	Claims          map[string]interface{} `json:"claims,omitempty"`
}

// AuthenticationResumer accepts a factor only from a trusted in-process
// authenticator after it verifies that factor for the continuation's user.
// Never bind the factor argument directly to unverified request input.
type AuthenticationResumer interface {
	Resume(context.Context, string, LoginChallengeType) (AuthenticationResult, *GoAuthError)
}
