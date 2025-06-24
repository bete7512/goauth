package config

// type RecaptchaProvider string like google, etc.
type RecaptchaProvider string

// type AuthProvider string like google, github, facebook, etc.
type AuthProvider string

// type DatabaseType string like postgres, mysql, sqlite, etc.
type DatabaseType string

// type AuthenticationType string like cookie, bearer, session, etc.
type AuthenticationType string

// type contextKey string like request_data, response_data, etc.
type contextKey string

// type SenderType string like SES, SendGrid, etc.
type SenderType string

// type RateLimiterStorageType string like redis, memory, database, etc.
type RateLimiterStorageType string
