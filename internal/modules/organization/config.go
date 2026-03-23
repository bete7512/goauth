package organization

import "time"

// Config holds configuration for the organization module.
type Config struct {
	// AutoCreateOrg creates a default org when a user signs up.
	AutoCreateOrg bool

	// DefaultOrgNamePattern is a simple pattern for auto-created org names.
	// Supports {name}, {email}, {username} placeholders.
	// Default: "{name}'s workspace"
	DefaultOrgNamePattern string

	// MaxMembersPerOrg limits members per org. -1 = unlimited (default).
	MaxMembersPerOrg int

	// InvitationExpiry is how long invitation tokens remain valid.
	// Default: 7 days.
	InvitationExpiry time.Duration

	// InvitationCallbackURL is the frontend URL for invitation acceptance.
	// Token appended as query param: {URL}?token=xxx
	// If empty, the accept endpoint returns JSON response.
	InvitationCallbackURL string
}

func (c *Config) applyDefaults() {
	if c.DefaultOrgNamePattern == "" {
		c.DefaultOrgNamePattern = "{name}'s workspace"
	}
	if c.MaxMembersPerOrg == 0 {
		c.MaxMembersPerOrg = -1
	}
	if c.InvitationExpiry == 0 {
		c.InvitationExpiry = 7 * 24 * time.Hour
	}
}
