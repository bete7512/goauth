package types

type ContextKey string

const (
	UserIDKey    ContextKey = "user_id"
	UserKey      ContextKey = "user"
	SessionIDKey ContextKey = "session_id"
)
