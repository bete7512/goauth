package ui

import (
	"fmt"
	"path"
	"strings"
)

// DefaultPageSize is the number of rows a list page shows.
const DefaultPageSize = 25

// Config holds configuration for the ui module. The zero value serves the
// admin console to super admins and nothing to anyone else.
type Config struct {
	// Path mounts the console at an absolute path of its own, such as
	// "/admin", outside the API's BasePath: "/admin", "/admin/login",
	// "/admin/users" and so on. Empty (the default) serves it at
	// BasePath + "/ui". The application's credential cookies must reach the
	// path, so Security.Session.Path must be "/" (the default) or a prefix of
	// it.
	Path string

	// UserPages lets users who are not super admins sign in through the
	// console and see their own account page. When false (the default), a
	// non-admin who signs in is signed straight back out and told that the
	// console is for administrators.
	UserPages bool

	// Title is the product name shown in the header and page titles.
	// Default: "GoAuth".
	Title string

	// PageSize is the number of rows list pages show. Default: 25, at most 100.
	PageSize int

	// TrustedOrigins are extra origins, such as "https://admin.example.com",
	// whose form submissions are accepted. Every page is protected by
	// net/http's CrossOriginProtection, which accepts same-origin requests
	// by comparing the Origin header with the request's Host. Add the public
	// origin here when a proxy in front of the application rewrites Host.
	TrustedOrigins []string
}

func (c *Config) applyDefaults() {
	c.Path = strings.TrimSpace(c.Path)
	if c.Path != "/" {
		c.Path = strings.TrimRight(c.Path, "/")
	}
	c.Title = strings.TrimSpace(c.Title)
	if c.Title == "" {
		c.Title = "GoAuth"
	}
	if c.PageSize <= 0 {
		c.PageSize = DefaultPageSize
	}
	if c.PageSize > 100 {
		c.PageSize = 100
	}
}

// validatePath checks a custom mount path: absolute, clean, not the host
// root, and free of route pattern syntax.
func validatePath(mount string) error {
	switch {
	case mount == "":
		return nil
	case mount == "/":
		return fmt.Errorf("config.Path cannot be the host root; use a path such as \"/admin\"")
	case !strings.HasPrefix(mount, "/"):
		return fmt.Errorf("config.Path %q must start with \"/\"", mount)
	case path.Clean(mount) != mount:
		return fmt.Errorf("config.Path %q must be a clean path, without \"..\", \".\" or repeated slashes", mount)
	case strings.ContainsAny(mount, "{}?#*\\ \t\r\n"):
		return fmt.Errorf("config.Path %q may only contain plain path segments", mount)
	}
	return nil
}

// cookieReaches reports whether a cookie scoped to cookiePath is sent with
// requests to mount.
func cookieReaches(cookiePath, mount string) bool {
	if cookiePath == "" || cookiePath == "/" {
		return true
	}
	cookiePath = strings.TrimRight(cookiePath, "/")
	return mount == cookiePath || strings.HasPrefix(mount, cookiePath+"/")
}
