package invitation

import "time"

// Config holds configuration for the standalone invitation module.
type Config struct {
	// InvitationExpiry is how long an invitation remains valid. Default: 7 days.
	InvitationExpiry time.Duration

	// CallbackURL is the frontend URL for invitation acceptance.
	// The token is appended as ?token=<token>.
	CallbackURL string

	// DefaultPurpose is used when no purpose is specified in a send request. Default: "platform".
	DefaultPurpose string

	// AllowedPurposes restricts which purpose values can be used.
	// If empty, any purpose string is allowed.
	AllowedPurposes []string

	// MaxPendingPerEmail limits how many pending invitations a single email can have.
	// -1 means unlimited. Default: -1.
	MaxPendingPerEmail int
}

func (c *Config) applyDefaults() {
	if c.InvitationExpiry <= 0 {
		c.InvitationExpiry = 7 * 24 * time.Hour
	}
	if c.DefaultPurpose == "" {
		c.DefaultPurpose = "platform"
	}
	if c.MaxPendingPerEmail == 0 {
		c.MaxPendingPerEmail = -1
	}
}
