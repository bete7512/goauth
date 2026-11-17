// Package idp exposes the identity provider module, which makes GoAuth an
// OpenID Connect provider: other applications sign users in with your
// accounts ("Sign in with your application") and receive an ID token that
// says who the user is.
// Import this package instead of internal/modules/idp.
//
// The module needs a signing key of its own (IDPModuleConfig.SigningKey).
// It serves the page where the user signs in and approves a request itself;
// set IDPModuleConfig.ConsentURL to use a page of your own frontend instead.
package idp

import (
	"context"
	"errors"

	internal "github.com/bete7512/goauth/internal/modules/idp"
	"github.com/bete7512/goauth/pkg/config"
)

// New creates the identity provider module. Config.APIURL and a signing key
// are required at Initialize.
func New(cfg *config.IDPModuleConfig) config.Module {
	return internal.New(cfg)
}

// RevokeUserGrants disconnects every client application of a user: their
// access and refresh tokens stop working at once, and the user is asked to
// approve each application again the next time they sign in to it. It
// returns how many applications were disconnected.
//
// Signing out does not disconnect applications by itself, and a password
// change ends their tokens but keeps the user's consent. Call this where
// your application wants more, for example when an account is closed or
// reported compromised.
//
// module must be the value returned by New, on an initialized Auth instance.
func RevokeUserGrants(ctx context.Context, module config.Module, userID string) (int64, error) {
	provider, ok := module.(*internal.IDPModule)
	if !ok {
		return 0, errors.New("idp: not an identity provider module")
	}
	revoked, authErr := provider.RevokeUserGrants(ctx, userID)
	if authErr != nil {
		return 0, authErr
	}
	return revoked, nil
}
