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

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
