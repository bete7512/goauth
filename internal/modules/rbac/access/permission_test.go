package access_test

import (
	"strings"
	"testing"

	"github.com/bete7512/goauth/internal/modules/rbac/access"
	"github.com/stretchr/testify/suite"
)

type PermissionSuite struct {
	suite.Suite
}

func TestPermissionSuite(t *testing.T) {
	suite.Run(t, new(PermissionSuite))
}

func (s *PermissionSuite) TestValidatePermission() {
	valid := []string{"invoice:read", "billing.invoice:approve", "line-item:bulk_update", "org2:read", "team:members.manage"}
	for _, permission := range valid {
		s.NoError(access.ValidatePermission(permission), permission)
	}
	invalid := []string{
		"", "invoice", ":read", "invoice:", "invoice:read:all", "Invoice:read", "invoice:Read",
		"*:read", "invoice:*", "*", "billing.*:read", "invoice..line:read", ".invoice:read",
		"invoice read:x", "_invoice:read", "invoice:-read", strings.Repeat("a", 130) + ":read",
	}
	for _, permission := range invalid {
		s.Error(access.ValidatePermission(permission), permission)
	}
}

func (s *PermissionSuite) TestValidateResource() {
	s.NoError(access.ValidateResource("invoice"))
	s.NoError(access.ValidateResource("billing.invoice"))
	s.Error(access.ValidateResource(""))
	s.Error(access.ValidateResource("*"))
	s.Error(access.ValidateResource("invoice:read"))
	s.Error(access.ValidateResource("Invoice"))
}

func (s *PermissionSuite) TestParseGrant() {
	cases := map[string]access.Grant{
		"*":                 {Resource: "*", Action: "*"},
		"*:*":               {Resource: "*", Action: "*"},
		"*:read":            {Resource: "*", Action: "read"},
		"invoice:*":         {Resource: "invoice", Action: "*"},
		"invoice:read":      {Resource: "invoice", Action: "read"},
		"billing.*:read":    {Resource: "billing.*", Action: "read"},
		"goauth.*:*":        {Resource: "goauth.*", Action: "*"},
		"goauth.roles:read": {Resource: "goauth.roles", Action: "read"},
	}
	for raw, want := range cases {
		got, err := access.ParseGrant(raw)
		s.NoError(err, raw)
		s.Equal(want, got, raw)
	}
	for _, raw := range []string{"", "invoice", "**", "*.*:read", "in*:read", "invoice:re*", ".*:read", "invoice:", "a:b:c", "Invoice:*"} {
		_, err := access.ParseGrant(raw)
		s.Error(err, raw)
	}
}

func (s *PermissionSuite) TestGrantString() {
	for _, raw := range []string{"*", "*:read", "invoice:*", "billing.*:read"} {
		grant, err := access.ParseGrant(raw)
		s.NoError(err)
		s.Equal(raw, grant.String())
	}
	grant, err := access.ParseGrant("*:*")
	s.NoError(err)
	s.Equal("*", grant.String(), "*:* is written back in its short form")
}

func (s *PermissionSuite) TestSetAllows() {
	cases := []struct {
		grants     []string
		permission string
		want       bool
	}{
		{[]string{"invoice:read"}, "invoice:read", true},
		{[]string{"invoice:read"}, "invoice:approve", false},
		{[]string{"invoice:read"}, "invoices:read", false},
		{[]string{"invoice:*"}, "invoice:approve", true},
		{[]string{"invoice:*"}, "project:read", false},
		{[]string{"*:read"}, "project:read", true},
		{[]string{"*:read"}, "project:write", false},
		{[]string{"*"}, "anything:at-all", true},
		{[]string{"billing.*:read"}, "billing.invoice:read", true},
		{[]string{"billing.*:read"}, "billing.invoice.line:read", true},
		{[]string{"billing.*:read"}, "billing:read", false},
		{[]string{"billing.*:read"}, "billingx.invoice:read", false},
		{[]string{"invoice:read", "project:write"}, "project:write", true},
		{nil, "invoice:read", false},
		{[]string{"*"}, "not-a-permission", false},
		{[]string{"*"}, "", false},
	}
	for _, c := range cases {
		set, err := access.ParseSet(c.grants)
		s.NoError(err)
		s.Equal(c.want, set.Allows(c.permission), "%v allows %s", c.grants, c.permission)
	}
}

// A bare wildcard must never reach GoAuth's own permissions: an organization
// admin who holds "*" over the application's resources cannot manage roles.
func (s *PermissionSuite) TestReservedNamespaceIsNotReachedByWildcards() {
	for _, grants := range [][]string{{"*"}, {"*:*"}, {"*:read"}, {"*:write"}} {
		set, err := access.ParseSet(grants)
		s.NoError(err)
		s.False(set.Allows(access.PermRolesRead), "%v", grants)
		s.False(set.Allows(access.PermRolesWrite), "%v", grants)
		s.False(set.Allows(access.PermAssignmentsWrite), "%v", grants)
		s.False(set.Allows("goauth:read"), "%v", grants)
	}

	explicit, err := access.ParseSet([]string{"goauth.*:*"})
	s.NoError(err)
	s.True(explicit.Allows(access.PermRolesWrite))
	s.True(explicit.Allows(access.PermAssignmentsRead))
	s.False(explicit.Allows("invoice:read"), "the reserved namespace does not leak the other way")

	narrow, err := access.ParseSet([]string{access.PermRolesRead})
	s.NoError(err)
	s.True(narrow.Allows(access.PermRolesRead))
	s.False(narrow.Allows(access.PermRolesWrite))

	s.True(access.IsReserved("goauth"))
	s.True(access.IsReserved("goauth.roles"))
	s.False(access.IsReserved("goauthx"))
	s.False(access.IsReserved("my.goauth"))
}

func (s *PermissionSuite) TestCovers() {
	cases := []struct {
		held  []string
		other string
		want  bool
	}{
		{[]string{"*"}, "invoice:read", true},
		{[]string{"*"}, "invoice:*", true},
		{[]string{"*"}, "*:read", true},
		{[]string{"*"}, "*", true},
		{[]string{"*"}, "billing.*:read", true},
		{[]string{"*"}, "goauth.roles:read", false},
		{[]string{"*"}, "goauth.*:*", false},
		{[]string{"goauth.*:*"}, "goauth.roles:write", true},
		{[]string{"goauth.*:*"}, "goauth.*:read", true},
		{[]string{"goauth.*:*"}, "*", false},
		{[]string{"*", "goauth.*:*"}, "goauth.assignments:write", true},
		{[]string{"invoice:*"}, "invoice:read", true},
		{[]string{"invoice:*"}, "invoice:*", true},
		{[]string{"invoice:*"}, "*:read", false},
		{[]string{"invoice:read"}, "invoice:*", false},
		{[]string{"invoice:read", "invoice:write"}, "invoice:*", false},
		{[]string{"*:read"}, "invoice:read", true},
		{[]string{"*:read"}, "invoice:write", false},
		{[]string{"*:read"}, "*", false},
		{[]string{"billing.*:*"}, "billing.invoice:read", true},
		{[]string{"billing.*:*"}, "billing.invoice.*:read", true},
		{[]string{"billing.*:*"}, "billing.*:read", true},
		{[]string{"billing.*:*"}, "billing:read", false},
		{[]string{"billing.*:*"}, "*:read", false},
		{[]string{"billing.invoice.*:*"}, "billing.*:read", false},
		{nil, "invoice:read", false},
	}
	for _, c := range cases {
		held, err := access.ParseSet(c.held)
		s.NoError(err)
		other, err := access.ParseGrant(c.other)
		s.NoError(err)
		s.Equal(c.want, held.Covers(other), "%v covers %s", c.held, c.other)
	}
}

func (s *PermissionSuite) TestCoversAllReportsTheFirstMissingGrant() {
	held, err := access.ParseSet([]string{"invoice:*", "project:read"})
	s.NoError(err)

	wanted, err := access.ParseSet([]string{"invoice:read", "project:read"})
	s.NoError(err)
	_, ok := held.CoversAll(wanted)
	s.True(ok)

	wanted, err = access.ParseSet([]string{"invoice:read", "project:write", "report:read"})
	s.NoError(err)
	missing, ok := held.CoversAll(wanted)
	s.False(ok)
	s.Equal("project:write", missing.String())
}

func (s *PermissionSuite) TestParseSetLenientDropsWhatItCannotRead() {
	set := access.ParseSetLenient([]string{"invoice:read", "NOT VALID", "", "project:*"})
	s.Equal([]string{"invoice:read", "project:*"}, set.Strings())
}

func (s *PermissionSuite) TestStringsAreSortedAndDeduplicated() {
	set, err := access.ParseSet([]string{"project:read", "*:*", "invoice:read", "*", "project:read"})
	s.NoError(err)
	s.Equal([]string{"*", "invoice:read", "project:read"}, set.Strings())
}

func (s *PermissionSuite) TestDecision() {
	allowed, reason := access.Keep.Apply(true)
	s.True(allowed)
	s.Empty(reason)

	allowed, _ = access.Keep.Apply(false)
	s.False(allowed)

	allowed, _ = access.Allow().Apply(false)
	s.True(allowed)

	allowed, reason = access.Deny("upgrade required").Apply(true)
	s.False(allowed)
	s.Equal("upgrade required", reason)
}

func (s *PermissionSuite) TestRoleAllowedIn() {
	s.True(access.Role{}.AllowedIn(access.ScopeGlobal))
	s.True(access.Role{}.AllowedIn(access.ScopeOrg))
	s.True(access.Role{Scope: access.ScopeOrg}.AllowedIn(access.ScopeOrg))
	s.False(access.Role{Scope: access.ScopeOrg}.AllowedIn(access.ScopeGlobal))
}
