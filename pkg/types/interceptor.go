package types

//go:generate mockgen -destination=../../internal/mocks/mock_interceptor.go -package=mocks github.com/bete7512/goauth/pkg/types AuthInterceptorRegistry

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
)

// AuthPhase indicates what stage of the auth flow the interceptor is running in.
type AuthPhase string

const (
	// PhaseLogin runs after identity verification (password, OAuth, magic link).
	// Interceptors may return challenges (2FA, org select) or enrich JWT claims.
	PhaseLogin AuthPhase = "login"

	// PhaseRefresh runs during token renewal.
	// Interceptors may enrich claims (carry forward org context) or validate
	// (e.g., confirm user is still an org member). Challenges are ignored.
	PhaseRefresh AuthPhase = "refresh"

	// PhaseResume runs after challenges are resolved (post-2FA, post-org-select).
	// Interceptors enrich claims only. Challenges are ignored.
	PhaseResume AuthPhase = "resume"
)

// LoginChallengeType identifies the kind of challenge a module issues.
type LoginChallengeType string

const (
	ChallengeTwoFactor LoginChallengeType = "2fa"
	ChallengeOrgSelect LoginChallengeType = "org_select"
)

// LoginChallenge represents a step the client must resolve before tokens are issued.
type LoginChallenge struct {
	Type LoginChallengeType     `json:"type"`
	Data map[string]interface{} `json:"data"`
}

// InterceptParams is the input to every AuthInterceptor.
type InterceptParams struct {
	// Phase indicates what stage of the auth flow we're in.
	Phase AuthPhase

	// User is the authenticated user.
	User *models.User

	// Metadata contains request context (IP, user agent, etc.).
	Metadata *RequestMetadata

	// ExistingClaims carries context from a previous token (refresh) or
	// challenge responses (resume). Nil on initial login.
	ExistingClaims map[string]interface{}
}

// InterceptResult is the output from an AuthInterceptor.
type InterceptResult struct {
	// Claims to merge into the JWT. Later interceptors (lower priority number)
	// override earlier ones for the same key.
	Claims map[string]interface{}

	// Challenge to present to the client. Only honored when Phase == PhaseLogin.
	// Nil means no challenge from this interceptor.
	Challenge *LoginChallenge
}

// AuthInterceptor is a function that modules register to participate in the
// auth flow. It can enrich JWT claims and/or issue login challenges.
type AuthInterceptor func(ctx context.Context, params *InterceptParams) (*InterceptResult, error)

// AuthInterceptorRegistry collects and runs interceptors in priority order.
type AuthInterceptorRegistry interface {
	// Register adds an interceptor. Higher priority runs first.
	Register(name string, interceptor AuthInterceptor, priority int)

	// Run executes all interceptors and returns merged claims + any challenges.
	// Challenges are only collected when params.Phase == PhaseLogin.
	Run(ctx context.Context, params *InterceptParams) (mergedClaims map[string]interface{}, challenges []LoginChallenge, err error)
}
