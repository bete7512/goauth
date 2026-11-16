package http_utils

import (
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/bete7512/goauth/pkg/types"
)

// LocalRedirectPath reports whether raw is a path on this server, such as
// "/admin/login/done?next=%2Fadmin", and returns it. Such a redirect is a
// server-rendered page of the application itself, so a sign-in that ends
// there sets cookies and sends no tokens in the URL. Anything with a scheme,
// a host, "//", a backslash or dot segments is refused, so the path can
// never lead to another site.
func LocalRedirectPath(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\t") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return "", false
	}
	if strings.Contains(parsed.Path, "//") || path.Clean(parsed.Path) != parsed.Path {
		return "", false
	}
	return raw, true
}

// FinishLocalSignIn ends a browser sign-in whose redirect is a local path
// (see LocalRedirectPath): it sets the credential cookies and redirects
// there with no tokens in the URL. When the sign-in still needs a second
// step, or cookies are not allowed, no credentials are set and the page is
// told why in its "error" query parameter.
func FinishLocalSignIn(w http.ResponseWriter, r *http.Request, security types.SecurityConfig, local, accessToken, refreshToken string, challenged bool) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case !CookiesEnabled(security.AuthMode):
		http.Redirect(w, r, withQuery(local, "error", "cookies_disabled"), http.StatusFound)
	case challenged || accessToken == "":
		http.Redirect(w, r, withQuery(local, "error", "challenge_required"), http.StatusFound)
	default:
		SetCredentialCookies(w, security, accessToken, refreshToken)
		http.Redirect(w, r, local, http.StatusFound)
	}
}

func withQuery(local, key, value string) string {
	sep := "?"
	if strings.Contains(local, "?") {
		sep = "&"
	}
	return local + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}
