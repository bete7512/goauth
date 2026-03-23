package types

type ContextKey string

const (
	UserIDKey    ContextKey = "user_id"
	UserKey      ContextKey = "user"
	SessionIDKey ContextKey = "session_id"
	OrgIDKey     ContextKey = "org_id"
	OrgRoleKey   ContextKey = "org_role"
	OrgKey       ContextKey = "organization"
	OrgMemberKey ContextKey = "org_member"
)
