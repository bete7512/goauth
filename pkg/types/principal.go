package types

import (
	"context"
	"time"
)

// Principal contains verified authentication state. Organizations are membership
// contexts within the default identity realm, never independent identity realms.
type Principal struct {
	Methods         []string
	OrganizationID  string
	UserID          string
	RealmID         string
	SessionID       string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	TokenVersion    int
}

type principalKey struct{}

// WithPrincipal returns a copy of ctx that carries principal.
func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

// PrincipalFromContext returns the principal stored by the authentication
// middleware, and whether there is one.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
