package testutil

import (
	"context"
	"net/http"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// ContextWithUserID returns a context with the user ID set (as auth middleware does).
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, types.UserIDKey, userID)
}

// ContextWithAdminUser returns a context with both user ID and full user object set
// (as auth middleware + admin middleware do together).
func ContextWithAdminUser(ctx context.Context, user *models.User) context.Context {
	ctx = context.WithValue(ctx, types.UserIDKey, user.ID)
	ctx = context.WithValue(ctx, types.UserKey, user)
	return ctx
}

// AuthenticatedRequest attaches user ID to the request context.
func AuthenticatedRequest(r *http.Request, userID string) *http.Request {
	return r.WithContext(ContextWithUserID(r.Context(), userID))
}

// AdminRequest attaches both user ID and full admin user to the request context.
func AdminRequest(r *http.Request, user *models.User) *http.Request {
	return r.WithContext(ContextWithAdminUser(r.Context(), user))
}

// TestAdminUser creates a super admin user with sensible defaults.
func TestAdminUser() *models.User {
	u := TestUser()
	u.IsSuperAdmin = true
	u.Email = "admin@example.com"
	u.Username = "admin"
	u.Name = "Admin User"
	return u
}
