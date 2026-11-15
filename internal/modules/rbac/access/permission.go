// Package access holds the vocabulary of the rbac module: the permission
// grammar, grant matching, scopes, roles and the values passed to callbacks.
// It has no dependencies on the rest of the module so that services, handlers
// and the public API can all share it.
package access

import (
	"fmt"
	"sort"
	"strings"
)

const (
	// ReservedNamespace is the resource prefix of GoAuth's own permissions.
	// A bare "*" never matches a resource in it; a grant has to name the
	// namespace ("goauth.*:*", "goauth.roles:read") to reach it.
	ReservedNamespace = "goauth"

	// Wildcard matches any resource or any action in a grant.
	Wildcard = "*"

	// MaxLength bounds a permission or grant string.
	MaxLength = 128

	separator    = ":"
	prefixSuffix = ".*"
)

// GoAuth's own permissions, checked by the role and assignment endpoints.
const (
	PermRolesRead        = ReservedNamespace + ".roles:read"
	PermRolesWrite       = ReservedNamespace + ".roles:write"
	PermAssignmentsRead  = ReservedNamespace + ".assignments:read"
	PermAssignmentsWrite = ReservedNamespace + ".assignments:write"
)

// Grant is a parsed grant pattern. Resource is "*", an exact resource or a
// prefix ending in ".*"; Action is "*" or an exact action.
type Grant struct {
	Resource string
	Action   string
}

// IsReserved reports whether resource belongs to GoAuth's own namespace.
func IsReserved(resource string) bool {
	return resource == ReservedNamespace || strings.HasPrefix(resource, ReservedNamespace+".")
}

// ValidatePermission checks a concrete permission such as "invoice:approve".
// Resources and actions are lowercase dot-separated names; wildcards are not
// allowed here, only in grants.
func ValidatePermission(permission string) error {
	resource, action, err := split(permission)
	if err != nil {
		return err
	}
	if err := validateName(resource); err != nil {
		return fmt.Errorf("permission %q: resource %w", permission, err)
	}
	if err := validateName(action); err != nil {
		return fmt.Errorf("permission %q: action %w", permission, err)
	}
	return nil
}

// ValidateResource checks a resource name such as "invoice" or "billing.invoice".
func ValidateResource(resource string) error {
	if len(resource) > MaxLength {
		return fmt.Errorf("resource %q is longer than %d characters", resource, MaxLength)
	}
	if err := validateName(resource); err != nil {
		return fmt.Errorf("resource %q %w", resource, err)
	}
	return nil
}

// ParseGrant parses a grant pattern. "*" is shorthand for "*:*".
func ParseGrant(grant string) (Grant, error) {
	if grant == Wildcard {
		return Grant{Resource: Wildcard, Action: Wildcard}, nil
	}
	resource, action, err := split(grant)
	if err != nil {
		return Grant{}, err
	}
	switch {
	case resource == Wildcard:
	case strings.HasSuffix(resource, prefixSuffix):
		if err := validateName(strings.TrimSuffix(resource, prefixSuffix)); err != nil {
			return Grant{}, fmt.Errorf("grant %q: resource %w", grant, err)
		}
	default:
		if err := validateName(resource); err != nil {
			return Grant{}, fmt.Errorf("grant %q: resource %w", grant, err)
		}
	}
	if action != Wildcard {
		if err := validateName(action); err != nil {
			return Grant{}, fmt.Errorf("grant %q: action %w", grant, err)
		}
	}
	return Grant{Resource: resource, Action: action}, nil
}

// String returns the canonical form of the grant.
func (g Grant) String() string {
	if g.Resource == Wildcard && g.Action == Wildcard {
		return Wildcard
	}
	return g.Resource + separator + g.Action
}

// Matches reports whether the grant allows action on resource.
func (g Grant) Matches(resource, action string) bool {
	if g.Action != Wildcard && g.Action != action {
		return false
	}
	switch {
	case g.Resource == Wildcard:
		return !IsReserved(resource)
	case strings.HasSuffix(g.Resource, prefixSuffix):
		return strings.HasPrefix(resource, strings.TrimSuffix(g.Resource, Wildcard))
	default:
		return g.Resource == resource
	}
}

// Covers reports whether every permission allowed by other is also allowed
// by g. It is what stops someone handing out more than they hold.
func (g Grant) Covers(other Grant) bool {
	if g.Action != Wildcard && g.Action != other.Action {
		return false
	}
	switch {
	case g.Resource == Wildcard:
		return !IsReserved(strings.TrimSuffix(other.Resource, prefixSuffix))
	case strings.HasSuffix(g.Resource, prefixSuffix):
		return strings.HasPrefix(other.Resource, strings.TrimSuffix(g.Resource, Wildcard))
	default:
		return g.Resource == other.Resource
	}
}

// Set is a collection of grants held together, for example by one user in
// one scope.
type Set []Grant

// ParseSet parses every grant, failing on the first invalid one.
func ParseSet(grants []string) (Set, error) {
	set := make(Set, 0, len(grants))
	for _, raw := range grants {
		grant, err := ParseGrant(raw)
		if err != nil {
			return nil, err
		}
		set = append(set, grant)
	}
	return set, nil
}

// ParseSetLenient parses the grants it can and drops the rest. It is used
// when reading stored roles, where a grant that no longer parses must reduce
// what the role allows rather than break every check.
func ParseSetLenient(grants []string) Set {
	set := make(Set, 0, len(grants))
	for _, raw := range grants {
		if grant, err := ParseGrant(raw); err == nil {
			set = append(set, grant)
		}
	}
	return set
}

// Allows reports whether any grant in the set allows permission. A malformed
// permission is never allowed.
func (s Set) Allows(permission string) bool {
	resource, action, err := split(permission)
	if err != nil {
		return false
	}
	for _, grant := range s {
		if grant.Matches(resource, action) {
			return true
		}
	}
	return false
}

// Covers reports whether a single grant in the set covers other.
func (s Set) Covers(other Grant) bool {
	for _, grant := range s {
		if grant.Covers(other) {
			return true
		}
	}
	return false
}

// CoversAll reports whether the set covers every grant in others, and
// returns the first one it does not.
func (s Set) CoversAll(others Set) (Grant, bool) {
	for _, other := range others {
		if !s.Covers(other) {
			return other, false
		}
	}
	return Grant{}, true
}

// Strings returns the grants in canonical form, de-duplicated and sorted.
func (s Set) Strings() []string {
	seen := make(map[string]struct{}, len(s))
	out := make([]string, 0, len(s))
	for _, grant := range s {
		text := grant.String()
		if _, dup := seen[text]; dup {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	sort.Strings(out)
	return out
}

func split(value string) (resource, action string, err error) {
	if value == "" {
		return "", "", fmt.Errorf("permission is empty")
	}
	if len(value) > MaxLength {
		return "", "", fmt.Errorf("permission %q is longer than %d characters", value, MaxLength)
	}
	resource, action, found := strings.Cut(value, separator)
	if !found || resource == "" || action == "" || strings.Contains(action, separator) {
		return "", "", fmt.Errorf("permission %q must have the form resource:action", value)
	}
	return resource, action, nil
}

// validateName accepts dot-separated segments of lowercase letters, digits,
// "_" and "-", each starting with a letter or digit.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("is empty")
	}
	for segment := range strings.SplitSeq(name, ".") {
		if segment == "" {
			return fmt.Errorf("%q has an empty segment", name)
		}
		for i, r := range segment {
			lowerOrDigit := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if lowerOrDigit || (i > 0 && (r == '_' || r == '-')) {
				continue
			}
			return fmt.Errorf("%q may only contain lowercase letters, digits, '_', '-' and '.'", name)
		}
	}
	return nil
}
