package http_utils

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type RedirectSuite struct {
	suite.Suite
}

func TestRedirectSuite(t *testing.T) {
	suite.Run(t, new(RedirectSuite))
}

func (s *RedirectSuite) TestLocalRedirectPath() {
	for _, ok := range []string{"/admin/login/done", "/admin/login/done?next=%2Fadmin%2Fusers", "/"} {
		got, accepted := LocalRedirectPath(ok)
		s.True(accepted, ok)
		s.Equal(ok, got)
	}
	for _, bad := range []string{"", "admin", "//evil.example", "/\\evil.example", "https://evil.example/", "/admin/../../x", "/admin//x", "/a\r\nLocation: x", "/admin#frag", "http:/x", "/./admin"} {
		_, accepted := LocalRedirectPath(bad)
		s.False(accepted, bad)
	}
}
