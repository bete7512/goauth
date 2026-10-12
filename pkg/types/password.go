package types

import (
	"fmt"
	"strings"
)

// Validate uses bytes, matching bcrypt's 72-byte limit. Passwords are never
// trimmed, normalized or truncated. The same policy applies to every write.
func (p PasswordPolicy) Validate(password string) error {
	min, max := p.MinLength, p.MaxLength
	if min <= 0 {
		min = 8
	}
	if max <= 0 || max > 72 {
		max = 72
	}
	if len(password) < min || len(password) > max {
		return fmt.Errorf("password must contain %d to %d bytes", min, max)
	}
	for _, rule := range []struct {
		enabled     bool
		chars, name string
	}{
		{p.RequireUppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "uppercase letter"},
		{p.RequireLowercase, "abcdefghijklmnopqrstuvwxyz", "lowercase letter"},
		{p.RequireNumbers, "0123456789", "number"},
		{p.RequireSpecial, "!@#$%^&*()_+-=[]{}|;:,.<>?", "special character"},
	} {
		if rule.enabled && !strings.ContainsAny(password, rule.chars) {
			return fmt.Errorf("password must contain a %s", rule.name)
		}
	}
	return nil
}
