package auth

import (
	"context"
	"fmt"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/types"
)

// SignIn runs the same password verification, policy and completion used by
// HTTP routes. A challenge is a successful operation with ChallengeRequired
// status, never a partially authenticated grant.
func (a *Auth) SignIn(ctx context.Context, request types.SignInRequest) (types.AuthenticationResult, error) {
	if !a.initialized.Load() {
		return types.AuthenticationResult{Status: types.Denied}, fmt.Errorf("authentication unavailable")
	}
	release, err := a.acquire(ctx, "password.signin")
	if err != nil {
		return types.AuthenticationResult{Status: types.Denied}, err
	}
	defer release()
	name := string(types.StatelessModule)
	if a.config.Security.AuthStrategy == types.StrategySession {
		name = string(types.SessionModule)
	}
	provider, ok := a.modules[name].(types.PasswordAuthenticator)
	if !ok {
		return types.AuthenticationResult{Status: types.Denied}, fmt.Errorf("password authentication unavailable")
	}
	return provider.SignIn(ctx, request)
}

// Authenticate validates an access credential and current account/session state.
// It never accepts refresh credentials or pending authentication continuations.
func (a *Auth) Authenticate(ctx context.Context, token string) (types.Principal, error) {
	if !a.initialized.Load() {
		return types.Principal{}, fmt.Errorf("authentication unavailable")
	}
	return security.ValidateAccess(ctx, a.config, a.moduleDependencies.SecurityManager, token)
}
