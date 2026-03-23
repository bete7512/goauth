package types

// OrgRole represents a user's role within an organization.
type OrgRole string

const (
	OrgRoleOwner  OrgRole = "owner"
	OrgRoleAdmin  OrgRole = "admin"
	OrgRoleMember OrgRole = "member"
)

// HasMinimumRole checks if the given role meets or exceeds the required minimum.
// Role hierarchy: owner > admin > member.
func HasMinimumRole(role string, minRole OrgRole) bool {
	roleWeight := map[string]int{
		string(OrgRoleOwner):  3,
		string(OrgRoleAdmin):  2,
		string(OrgRoleMember): 1,
	}
	return roleWeight[role] >= roleWeight[string(minRole)]
}

// IsValidOrgRole returns true if the role string is a recognized org role.
func IsValidOrgRole(role string) bool {
	switch OrgRole(role) {
	case OrgRoleOwner, OrgRoleAdmin, OrgRoleMember:
		return true
	}
	return false
}
