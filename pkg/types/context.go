package types

// ContextKey is the type of the request-context keys GoAuth sets.
type ContextKey string

// Request-context keys set by the authentication middleware and Auth.Routes.
const (
	UserIDKey    ContextKey = "user_id"
	UserKey      ContextKey = "user"
	SessionIDKey ContextKey = "session_id"
	OrgIDKey     ContextKey = "org_id"
	OrgRoleKey   ContextKey = "org_role"
	OrgKey       ContextKey = "organization"
	OrgMemberKey ContextKey = "org_member"
	RouteNameKey ContextKey = "route_name"
)
