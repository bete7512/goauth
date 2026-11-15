// Package oauthproto holds the OAuth 2.1 protocol rules shared by the
// authorization server module and the resource server kit: resource
// indicators, redirect URIs, PKCE and scope strings.
package oauthproto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Token type identifiers (RFC 8693 section 3) and JOSE types.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"

	// AccessTokenJOSEType is the "typ" of RFC 9068 JWT access tokens.
	AccessTokenJOSEType = "at+jwt"
	// IDJAGJOSEType is the "typ" of an Identity Assertion JWT Authorization Grant.
	IDJAGJOSEType = "oauth-id-jag+jwt"

	// ClientAssertionTypeJWTBearer is the client_assertion_type of private_key_jwt.
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// GrantProfileIDJAG advertises ID-JAG support in authorization server metadata.
	GrantProfileIDJAG = "urn:ietf:params:oauth:grant-profile:id-jag"

	// ScopeOfflineAccess asks for a refresh token; it is not a resource scope.
	ScopeOfflineAccess = "offline_access"
)

// Limits on values taken from requests.
const (
	MaxURILength   = 2048
	MaxScopeLength = 1024
	MaxScopeCount  = 64
	// MaxResourceLength matches the indexed column that stores resource URIs.
	MaxResourceLength = 512
)

// CanonicalResource validates an RFC 8707 resource indicator and returns its
// canonical form: lowercase scheme and host, no fragment, and no trailing
// slash when the path is just "/". Paths are otherwise kept as given.
func CanonicalResource(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("resource is empty")
	}
	if len(raw) > MaxResourceLength {
		return "", errors.New("resource is too long")
	}
	if strings.ContainsAny(raw, " \t\r\n") || hasControl(raw) {
		return "", errors.New("resource contains whitespace or control characters")
	}
	if strings.Contains(raw, "#") {
		return "", errors.New("resource must not contain a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("resource is not a valid URI: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", errors.New("resource must be an absolute http or https URI")
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", errors.New("resource must have a host")
	}
	if u.User != nil {
		return "", errors.New("resource must not contain credentials")
	}
	if u.Opaque != "" {
		return "", errors.New("resource must be a hierarchical URI")
	}
	canonical := scheme + "://" + strings.ToLower(u.Host)
	if path := u.EscapedPath(); path != "" && path != "/" {
		canonical += path
	}
	if u.RawQuery != "" {
		canonical += "?" + u.RawQuery
	}
	return canonical, nil
}

// ResourcePath returns the path component of a canonical resource, or "".
func ResourcePath(canonical string) string {
	u, err := url.Parse(canonical)
	if err != nil {
		return ""
	}
	path := u.EscapedPath()
	if path == "/" {
		return ""
	}
	return path
}

// ResourceOrigin returns scheme://host of a canonical resource.
func ResourceOrigin(canonical string) string {
	u, err := url.Parse(canonical)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// deniedRedirectSchemes are never accepted in a redirect URI: schemes that
// run script or read local data in a browser, network protocols, and schemes
// the operating system hands to a built-in handler (settings panes, dialers,
// file shares, shells). A private-use scheme is meant to open the client's
// own application; none of these is one.
var deniedRedirectSchemes = map[string]bool{
	"javascript": true, "data": true, "vbscript": true, "file": true, "about": true,
	"blob": true, "ftp": true, "ws": true, "wss": true, "mailto": true, "tel": true,
	"view-source": true, "filesystem": true, "jar": true,
	"sms": true, "smsto": true, "mms": true, "callto": true, "facetime": true, "facetime-audio": true, "sip": true, "sips": true,
	"smb": true, "nfs": true, "afp": true, "sftp": true, "tftp": true, "ftps": true, "ssh": true, "telnet": true,
	"ldap": true, "ldaps": true, "rdp": true, "vnc": true, "git": true, "svn": true, "news": true, "nntp": true, "irc": true, "ircs": true,
	"search": true, "search-ms": true, "shell": true, "res": true, "cid": true, "mid": true, "ms-msdt": true,
	"chrome": true, "chrome-extension": true, "moz-extension": true, "edge": true, "resource": true,
	"intent": true, "market": true, "itms": true, "itms-apps": true, "itms-services": true, "itms-beta": true,
	"magnet": true, "webcal": true, "geo": true, "maps": true, "x-apple-reminder": true,
}

// deniedRedirectSchemePrefixes covers families of operating system handlers.
var deniedRedirectSchemePrefixes = []string{"ms-", "x-apple.", "x-apple-", "android-app"}

func redirectSchemeDenied(scheme string) bool {
	if deniedRedirectSchemes[scheme] {
		return true
	}
	for _, prefix := range deniedRedirectSchemePrefixes {
		if strings.HasPrefix(scheme, prefix) {
			return true
		}
	}
	return false
}

// ValidateRedirectURI checks a redirect URI at registration time. It accepts
// https URIs, http URIs on a loopback host (RFC 8252 section 7.3) and
// private-use URI schemes of native apps (RFC 8252 section 7.1).
func ValidateRedirectURI(raw string) error {
	if raw == "" {
		return errors.New("redirect URI is empty")
	}
	if len(raw) > MaxURILength {
		return errors.New("redirect URI is too long")
	}
	if strings.ContainsAny(raw, " \t\r\n") || hasControl(raw) {
		return errors.New("redirect URI contains whitespace or control characters")
	}
	if strings.Contains(raw, "#") {
		return errors.New("redirect URI must not contain a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect URI is not a valid URI: %w", err)
	}
	if u.Scheme == "" {
		return errors.New("redirect URI must be absolute")
	}
	if u.User != nil {
		return errors.New("redirect URI must not contain credentials")
	}
	switch scheme := strings.ToLower(u.Scheme); scheme {
	case "https":
		if u.Hostname() == "" {
			return errors.New("redirect URI must have a host")
		}
	case "http":
		if !IsLoopbackHost(u.Hostname()) {
			return errors.New("http redirect URIs are only allowed on a loopback host")
		}
	default:
		if redirectSchemeDenied(scheme) {
			return fmt.Errorf("redirect URI scheme %q is not allowed", scheme)
		}
	}
	return nil
}

// IsLoopbackHost reports whether host is "localhost" or a loopback IP literal.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsLoopbackRedirect reports whether a redirect URI points at a loopback host
// over http, the form native clients use with a random port.
func IsLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.EqualFold(u.Scheme, "http") && IsLoopbackHost(u.Hostname())
}

// RedirectHost returns what to show the user as the destination of a
// redirect URI: the hostname for http and https URIs, and the scheme for
// everything else. A private-use URI may carry anything in the position of
// a host ("app://accounts.example.com/callback"), and that text names no
// server, so it is never shown as one.
func RedirectHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if scheme := strings.ToLower(u.Scheme); scheme == "https" || scheme == "http" {
		return u.Hostname()
	}
	return strings.ToLower(u.Scheme) + ":"
}

// IsPrivateSchemeRedirect reports whether a redirect URI uses a private-use
// URI scheme, which opens an application on the user's device (RFC 8252
// section 7.1).
func IsPrivateSchemeRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme != "https" && scheme != "http"
}

// MatchRedirectURI reports whether presented equals one of the registered
// redirect URIs. Comparison is exact, except that a loopback http URI matches
// a registered loopback URI on any port (RFC 8252 section 7.3).
func MatchRedirectURI(registered []string, presented string) bool {
	if presented == "" {
		return false
	}
	for _, candidate := range registered {
		if candidate == presented {
			return true
		}
	}
	if !IsLoopbackRedirect(presented) {
		return false
	}
	p, err := url.Parse(presented)
	if err != nil || p.User != nil || p.Fragment != "" || strings.Contains(presented, "#") {
		return false
	}
	for _, candidate := range registered {
		if !IsLoopbackRedirect(candidate) {
			continue
		}
		c, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		if strings.EqualFold(c.Hostname(), p.Hostname()) && c.EscapedPath() == p.EscapedPath() && c.RawQuery == p.RawQuery {
			return true
		}
	}
	return false
}

// AppendQuery adds params to the query of a redirect URI, keeping any query
// it already has.
func AppendQuery(redirectURI string, params url.Values) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	query := u.Query()
	for key, values := range params {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

// ValidCodeChallenge reports whether s is a well-formed S256 code challenge:
// 43 base64url characters.
func ValidCodeChallenge(s string) bool {
	return len(s) == 43 && isUnreserved(s, false)
}

// ValidCodeVerifier reports whether s is a well-formed code verifier:
// 43 to 128 unreserved characters (RFC 7636 section 4.1).
func ValidCodeVerifier(s string) bool {
	return len(s) >= 43 && len(s) <= 128 && isUnreserved(s, true)
}

// VerifyPKCE reports whether verifier hashes to the S256 challenge.
func VerifyPKCE(verifier, challenge string) bool {
	if !ValidCodeVerifier(verifier) || !ValidCodeChallenge(challenge) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// isUnreserved checks for ALPHA / DIGIT / "-" / "_" and, when dots is set,
// "." / "~" as well.
func isUnreserved(s string, dots bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		case dots && (c == '.' || c == '~'):
		default:
			return false
		}
	}
	return true
}

// ParseScope splits a space-delimited scope string, dropping duplicates and
// keeping order. It rejects strings that are too long or contain characters
// outside the scope-token grammar of RFC 6749 section 3.3.
func ParseScope(scope string) ([]string, error) {
	if len(scope) > MaxScopeLength {
		return nil, errors.New("scope is too long")
	}
	fields := strings.Fields(scope)
	if len(fields) > MaxScopeCount {
		return nil, errors.New("too many scopes")
	}
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, token := range fields {
		if !ValidScopeToken(token) {
			return nil, fmt.Errorf("invalid scope %q", token)
		}
		if !seen[token] {
			seen[token] = true
			out = append(out, token)
		}
	}
	return out, nil
}

// ValidScopeToken reports whether s is one scope-token: printable ASCII
// without space, double quote or backslash.
func ValidScopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// JoinScope renders scopes as a space-delimited string.
func JoinScope(scopes []string) string {
	return strings.Join(scopes, " ")
}

// ScopeSubset reports whether every scope in requested is in granted.
func ScopeSubset(requested, granted []string) bool {
	set := make(map[string]bool, len(granted))
	for _, scope := range granted {
		set[scope] = true
	}
	for _, scope := range requested {
		if !set[scope] {
			return false
		}
	}
	return true
}

// ExpandScopes returns scopes plus every scope they imply through the
// hierarchy (scope name to the narrower scopes it includes), transitively.
func ExpandScopes(scopes []string, hierarchy map[string][]string) map[string]bool {
	out := make(map[string]bool, len(scopes))
	var visit func(string)
	visit = func(scope string) {
		if out[scope] {
			return
		}
		out[scope] = true
		for _, implied := range hierarchy[scope] {
			visit(implied)
		}
	}
	for _, scope := range scopes {
		visit(scope)
	}
	return out
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
