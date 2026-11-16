package ui

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type HelpersSuite struct {
	suite.Suite
}

func TestHelpersSuite(t *testing.T) {
	suite.Run(t, new(HelpersSuite))
}

func (s *HelpersSuite) TestSafeNextKeepsVisitorsInsideTheConsole() {
	m := &UIModule{base: "/auth/ui"}
	for _, next := range []string{"/auth/ui", "/auth/ui", "/auth/ui/users?q=ada&offset=25", "/auth/ui/account"} {
		s.Equal(next, m.safeNext(next), next)
	}
	for _, next := range []string{
		"", "/", "/auth", "/auth/uix", "/auth/ui-other", "/auth/other",
		"https://evil.example/auth/ui", "//evil.example/auth/ui", "/auth/ui//evil.example",
		"/auth/ui/../../x", "/auth/ui/./admin", "/auth/ui/%2e%2e/x", "/auth/ui\\evil", "/auth/ui/admin\r\nX: y",
		"/auth/ui/login", "/auth/ui/login/2fa", "javascript:alert(1)",
	} {
		s.Empty(m.safeNext(next), next)
	}
}

func (s *HelpersSuite) TestLandingRespectsWhoTheVisitorIs() {
	m := &UIModule{base: "/auth/ui"}
	admin := &visitor{User: adminUser()}
	plain := &visitor{User: plainUser()}
	s.Equal("/auth/ui", m.landing(admin, ""))
	s.Equal("/auth/ui/users", m.landing(admin, "/auth/ui/users"))
	s.Equal("/auth/ui/account", m.landing(plain, ""))
	s.Equal("/auth/ui/account", m.landing(plain, "/auth/ui/users"), "a plain user is never sent to an admin page")
	s.Equal("/auth/ui/account", m.landing(plain, "/auth/ui/account"))
}

func (s *HelpersSuite) TestSplitGrants() {
	s.Equal([]string{"invoice:*", "report:read", "project:write"}, splitGrants(" invoice:* \r\nreport:read,project:write\n\n , "))
	s.Empty(splitGrants(""))
	s.Empty(splitGrants(" \n , "))
}

func (s *HelpersSuite) TestInitials() {
	cases := map[[2]string]string{
		{"Ada Lovelace", "ada@example.com"}: "AL",
		{"Mary Kenneth Keller", ""}:         "MK",
		{"", "grace.hopper@example.com"}:    "GH",
		{"cher", ""}:                        "C",
		{"", ""}:                            "?",
		{"  ", "  "}:                        "?",
		{"émile zola", ""}:                  "ÉZ",
	}
	for input, want := range cases {
		s.Equal(want, initials(input[0], input[1]), input)
	}
}

func (s *HelpersSuite) TestAgo() {
	s.Equal("just now", ago(10*time.Second))
	s.Equal("1 minute ago", ago(time.Minute))
	s.Equal("5 minutes ago", ago(5*time.Minute))
	s.Equal("3 hours ago", ago(3*time.Hour))
	s.Equal("2 days ago", ago(49*time.Hour))
	s.Equal("1 month ago", ago(31*24*time.Hour))
	s.Equal("2 years ago", ago(2*366*24*time.Hour))
}

func (s *HelpersSuite) TestPager() {
	first := pager{Offset: 0, Limit: 25, Total: 60, Path: "/auth/ui/users", Query: "q=ada"}
	s.EqualValues(1, first.From())
	s.EqualValues(25, first.To())
	s.False(first.HasPrev())
	s.True(first.HasNext())
	s.Equal("/auth/ui/users?q=ada&offset=25", first.NextLink())

	last := pager{Offset: 50, Limit: 25, Total: 60, Path: "/auth/ui/users"}
	s.EqualValues(51, last.From())
	s.EqualValues(60, last.To())
	s.False(last.HasNext())
	s.Equal("/auth/ui/users?offset=25", last.PrevLink())

	second := pager{Offset: 25, Limit: 25, Total: 60, Path: "/p"}
	s.Equal("/p", second.PrevLink(), "the first page has no offset parameter")

	empty := pager{Limit: 25}
	s.EqualValues(0, empty.From())
	s.EqualValues(0, empty.To())
}

func (s *HelpersSuite) TestConfigDefaults() {
	module := New(nil)
	s.Equal("GoAuth", module.config.Title)
	s.Equal(DefaultPageSize, module.config.PageSize)

	cfg := &Config{Title: "  Acme ", PageSize: 500, TrustedOrigins: []string{"https://admin.example.com"}}
	module = New(cfg)
	s.Equal("Acme", module.config.Title)
	s.Equal(100, module.config.PageSize)
	cfg.TrustedOrigins[0] = "https://changed.example"
	s.Equal("https://admin.example.com", module.config.TrustedOrigins[0], "the configuration is copied")
}

func (s *HelpersSuite) TestTemplatesAndAssetsLoad() {
	module := New(nil)
	pages, err := loadPages(templateFS, module.funcs())
	s.Require().NoError(err)
	for _, page := range []string{"login", "dashboard", "users", "user", "audit", "roles", "account", "error"} {
		s.Contains(pages.pages, page)
	}
	s.NotNil(pages.pages["users"].Lookup(usersTable), "the users page defines its table fragment")
	s.NotNil(pages.pages["audit"].Lookup(auditTable), "the audit page defines its table fragment")

	assets, err := loadAssets(assetFS)
	s.Require().NoError(err)
	s.Len(assets.files, 3, "only css and js files are served; the notice file is not")
	for _, file := range assets.files {
		s.Len(file.version, 12)
	}
}

func (s *HelpersSuite) TestValidatePath() {
	for _, mount := range []string{"", "/admin", "/console", "/internal/admin", "/admin-console"} {
		s.NoError(validatePath(mount), mount)
	}
	for _, mount := range []string{"/", "admin", "/admin/../x", "/admin//x", "/./admin", "/admin/{id}", "/admin?x=1", "/ad min", "/admin*"} {
		s.Error(validatePath(mount), mount)
	}
	module := New(&Config{Path: " /admin/ "})
	s.Equal("/admin", module.config.Path, "surrounding spaces and a trailing slash are dropped")
}

func (s *HelpersSuite) TestCookieReaches() {
	s.True(cookieReaches("/", "/admin"))
	s.True(cookieReaches("", "/admin"))
	s.True(cookieReaches("/auth", "/auth/ui"))
	s.True(cookieReaches("/auth/", "/auth/ui"))
	s.True(cookieReaches("/admin", "/admin"))
	s.False(cookieReaches("/auth", "/admin"))
	s.False(cookieReaches("/auth", "/authx/ui"), "a cookie path matches whole segments only")
	s.False(cookieReaches("/api/v1", "/admin"))
}

func (s *HelpersSuite) TestHumanDuration() {
	s.Equal("15 minutes", humanDuration(15*time.Minute))
	s.Equal("7 days", humanDuration(168*time.Hour))
	s.Equal("1 hour 30 minutes", humanDuration(90*time.Minute))
	s.Equal("1 day 1 hour", humanDuration(25*time.Hour+30*time.Minute), "two units at most")
	s.Equal("not set", humanDuration(0))
}
