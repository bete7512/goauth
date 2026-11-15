package oauthproto

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalResource(t *testing.T) {
	valid := map[string]string{
		"https://mcp.example.com":             "https://mcp.example.com",
		"https://mcp.example.com/":            "https://mcp.example.com",
		"HTTPS://MCP.Example.COM/mcp":         "https://mcp.example.com/mcp",
		"https://mcp.example.com:8443":        "https://mcp.example.com:8443",
		"https://mcp.example.com/server/mcp":  "https://mcp.example.com/server/mcp",
		"https://mcp.example.com/Case/Kept/":  "https://mcp.example.com/Case/Kept/",
		"http://localhost:3000/mcp":           "http://localhost:3000/mcp",
		"https://api.example.com/v1?tenant=a": "https://api.example.com/v1?tenant=a",
		"https://mcp.example.com/a%20b":       "https://mcp.example.com/a%20b",
	}
	for input, want := range valid {
		got, err := CanonicalResource(input)
		require.NoError(t, err, input)
		require.Equal(t, want, got, input)
		again, err := CanonicalResource(got)
		require.NoError(t, err)
		require.Equal(t, got, again, "canonical form is stable")
	}
	for _, input := range []string{
		"", "mcp.example.com", "https://mcp.example.com#fragment", "https://mcp.example.com/#", "urn:example:resource",
		"https://user:pw@mcp.example.com", "https:///path", "ftp://mcp.example.com", "https://mcp.example.com/a b",
		"https://mcp.example.com/\n", "https://" + strings.Repeat("a", 600) + ".example.com",
	} {
		_, err := CanonicalResource(input)
		require.Error(t, err, input)
	}
	require.Equal(t, "/server/mcp", ResourcePath("https://mcp.example.com/server/mcp"))
	require.Equal(t, "", ResourcePath("https://mcp.example.com"))
	require.Equal(t, "https://mcp.example.com:8443", ResourceOrigin("https://mcp.example.com:8443/x"))
}

func TestValidateRedirectURI(t *testing.T) {
	for _, uri := range []string{
		"https://claude.ai/api/mcp/auth_callback", "https://app.example.com/cb?x=1", "http://127.0.0.1:33418/callback",
		"http://localhost:6274/oauth/callback", "http://[::1]:8000/cb", "http://127.0.0.1/cb", "cursor://anysphere.cursor-retrieval/oauth/callback",
		"com.example.app:/oauth2redirect", "vscode://vscode.github-authentication/did-authenticate",
	} {
		require.NoError(t, ValidateRedirectURI(uri), uri)
	}
	for _, uri := range []string{
		"", "/relative", "http://example.com/cb", "http://192.168.1.4/cb", "https://app.example.com/cb#frag", "javascript:alert(1)",
		"data:text/html,x", "file:///etc/passwd", "https://user@app.example.com/cb", "https:///cb", "https://app.example.com/a b",
		"vbscript:x", "https://" + strings.Repeat("a", 2100),
	} {
		require.Error(t, ValidateRedirectURI(uri), uri)
	}
}

func TestMatchRedirectURI(t *testing.T) {
	registered := []string{"https://app.example.com/cb", "http://127.0.0.1/callback", "http://localhost:6274/oauth/callback?x=1", "cursor://host/cb"}
	require.True(t, MatchRedirectURI(registered, "https://app.example.com/cb"))
	require.True(t, MatchRedirectURI(registered, "cursor://host/cb"))
	require.True(t, MatchRedirectURI(registered, "http://127.0.0.1:51234/callback"), "loopback ports are free")
	require.True(t, MatchRedirectURI(registered, "http://localhost:1/oauth/callback?x=1"))

	require.False(t, MatchRedirectURI(registered, ""))
	require.False(t, MatchRedirectURI(registered, "https://app.example.com/cb/"))
	require.False(t, MatchRedirectURI(registered, "https://app.example.com:8443/cb"), "ports matter off loopback")
	require.False(t, MatchRedirectURI(registered, "https://app.example.com/cb?extra=1"))
	require.False(t, MatchRedirectURI(registered, "http://127.0.0.1:51234/other"))
	require.False(t, MatchRedirectURI(registered, "http://localhost:51234/callback"), "localhost and 127.0.0.1 are different registrations")
	require.False(t, MatchRedirectURI(registered, "http://localhost:1/oauth/callback"), "query must match")
	require.False(t, MatchRedirectURI(registered, "http://evil.example.com:51234/callback"))
	require.False(t, MatchRedirectURI(registered, "http://127.0.0.1.evil.example.com/callback"))
	require.False(t, MatchRedirectURI(registered, "http://user@127.0.0.1:5/callback"))
	require.False(t, MatchRedirectURI([]string{"https://app.example.com/cb"}, "http://127.0.0.1/cb"))

	require.True(t, IsLoopbackRedirect("http://127.0.0.1:1/x"))
	require.True(t, IsLoopbackRedirect("http://[::1]/x"))
	require.False(t, IsLoopbackRedirect("https://127.0.0.1/x"))
	require.Equal(t, "127.0.0.1", RedirectHost("http://127.0.0.1:99/cb"))
	require.Equal(t, "claude.ai", RedirectHost("https://claude.ai/cb"))
	require.Equal(t, "com.example.app:", RedirectHost("com.example.app:/cb"))
}

func TestAppendQuery(t *testing.T) {
	got, err := AppendQuery("https://app.example.com/cb?keep=1", url.Values{"code": {"abc"}, "state": {"a b&c"}})
	require.NoError(t, err)
	parsed, err := url.Parse(got)
	require.NoError(t, err)
	require.Equal(t, "1", parsed.Query().Get("keep"))
	require.Equal(t, "abc", parsed.Query().Get("code"))
	require.Equal(t, "a b&c", parsed.Query().Get("state"))

	native, err := AppendQuery("com.example.app:/cb", url.Values{"code": {"x"}})
	require.NoError(t, err)
	require.Equal(t, "com.example.app:/cb?code=x", native)
}

func TestPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	require.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge, "RFC 7636 appendix B vector")
	require.True(t, VerifyPKCE(verifier, challenge))
	require.False(t, VerifyPKCE(verifier+"x", challenge))
	require.False(t, VerifyPKCE("short", challenge))
	require.False(t, VerifyPKCE(verifier, challenge[:42]))
	require.False(t, VerifyPKCE(verifier, strings.Repeat("=", 43)))
	require.False(t, VerifyPKCE(strings.Repeat("a", 129), challenge))
	require.True(t, ValidCodeVerifier(strings.Repeat("a-._~", 9)))
	require.False(t, ValidCodeVerifier(strings.Repeat("a+", 30)))
	require.False(t, ValidCodeChallenge(strings.Repeat("a", 42)+"."))
}

func TestScopes(t *testing.T) {
	scopes, err := ParseScope("  files:read files:write   files:read ")
	require.NoError(t, err)
	require.Equal(t, []string{"files:read", "files:write"}, scopes)
	empty, err := ParseScope("")
	require.NoError(t, err)
	require.Empty(t, empty)
	_, err = ParseScope("bad\"scope")
	require.Error(t, err)
	_, err = ParseScope("bad\\scope")
	require.Error(t, err)
	_, err = ParseScope("unicodé")
	require.Error(t, err)
	_, err = ParseScope(strings.Repeat("a ", 70))
	require.Error(t, err)
	_, err = ParseScope(strings.Repeat("a", 2000))
	require.Error(t, err)

	require.Equal(t, "a b", JoinScope([]string{"a", "b"}))
	require.True(t, ScopeSubset([]string{"a"}, []string{"a", "b"}))
	require.True(t, ScopeSubset(nil, nil))
	require.False(t, ScopeSubset([]string{"c"}, []string{"a", "b"}))

	expanded := ExpandScopes([]string{"admin"}, map[string][]string{"admin": {"write"}, "write": {"read"}, "read": {"admin"}})
	require.Equal(t, map[string]bool{"admin": true, "write": true, "read": true}, expanded, "cycles terminate")
	require.Equal(t, map[string]bool{"read": true}, ExpandScopes([]string{"read"}, map[string][]string{"write": {"read"}}))
}

// What the consent page shows as the destination must not be text a client
// can choose. For a private-use URI the "host" position names no server.
func TestRedirectDestinationShownToUsers(t *testing.T) {
	require.Equal(t, "app.example.com", RedirectHost("https://app.example.com/callback"))
	require.Equal(t, "127.0.0.1", RedirectHost("http://127.0.0.1:53124/callback"))
	require.Equal(t, "evilapp:", RedirectHost("evilapp://accounts.google.com/callback"), "not accounts.google.com")
	require.Equal(t, "com.example.app:", RedirectHost("com.example.app:/oauth/callback"))
	require.Equal(t, "cursor:", RedirectHost("Cursor://anysphere.cursor-mcp/oauth/callback"))

	require.True(t, IsPrivateSchemeRedirect("evilapp://accounts.google.com/callback"))
	require.True(t, IsPrivateSchemeRedirect("com.example.app:/oauth/callback"))
	require.False(t, IsPrivateSchemeRedirect("https://app.example.com/callback"))
	require.False(t, IsPrivateSchemeRedirect("http://localhost/callback"))
	require.False(t, IsPrivateSchemeRedirect("/relative"))
}

// A private-use scheme opens the client's own application. Schemes that the
// operating system hands to a built-in handler are not that.
func TestRedirectSchemesHandledByTheOperatingSystemAreRefused(t *testing.T) {
	for _, uri := range []string{
		"ms-settings:privacy-webcam", "ms-msdt:/id", "search-ms:query=x", "smb://fileserver/share", "sms:+15550100",
		"ssh://host", "telnet://host", "tel:+15550100", "facetime:user@example.com", "intent://scan/#Intent;end",
		"itms-services://?action=download-manifest", "chrome://settings", "file:///etc/passwd", "javascript:alert(1)",
		"data:text/html,x", "ldap://host/dc=example", "x-apple.systempreferences:com.apple.preference.security",
	} {
		require.Error(t, ValidateRedirectURI(uri), uri)
	}
	// Application schemes real clients use still pass.
	for _, uri := range []string{"cursor://anysphere.cursor-mcp/oauth/callback", "vscode://vscode.github-authentication/did-authenticate", "com.example.app:/oauth/callback", "myapp://callback"} {
		require.NoError(t, ValidateRedirectURI(uri), uri)
	}
}
