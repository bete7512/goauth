package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// The redirect URI of a pending request is written into the page's
// Content-Security-Policy. Only an origin or a scheme may come out of it,
// and nothing that could end the directive or start another.
func TestCSPSource(t *testing.T) {
	cases := map[string]string{
		"https://rp.example.com/callback":            "https://rp.example.com",
		"https://rp.example.com:8443/cb?x=1":         "https://rp.example.com:8443",
		"HTTPS://RP.example.com/cb":                  "https://RP.example.com",
		"http://localhost:3000/login/generic_oauth":  "http://localhost:3000",
		"http://127.0.0.1:53211/cb":                  "http://127.0.0.1:53211",
		"http://[::1]:8080/cb":                       "http://[::1]:8080",
		"com.example.app:/oauth/callback":            "com.example.app:",
		"myapp://callback":                           "myapp:",
		"":                                           "",
		"/relative/path":                             "",
		"https://":                                   "",
		"https://rp.example.com;script-src *":        "",
		"https://rp.example.com, https://evil.test/": "",
		"https://rp.example.com' 'unsafe-inline/cb":  "",
		// Credentials in the address are never copied.
		"https://user:pass@rp.example.com/cb": "https://rp.example.com",
		"ht tp://rp.example.com/cb":           "",
		"https://rp.example.com:notaport/cb":  "",
	}
	for redirectURI, want := range cases {
		require.Equal(t, want, cspSource(redirectURI), redirectURI)
	}
}

func TestPageHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	pageHeaders(w, "https://rp.example.com/callback")
	policy := w.Header().Get("Content-Security-Policy")
	require.Contains(t, policy, "default-src 'none'")
	require.Contains(t, policy, "form-action 'self' https://rp.example.com;")
	require.Contains(t, policy, "frame-ancestors 'none'")
	require.NotContains(t, policy, "script-src", "no script is allowed at all")
	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	// A redirect URI that cannot be written safely is left out, never copied.
	w = httptest.NewRecorder()
	pageHeaders(w, "https://rp.example.com;script-src *")
	require.Contains(t, w.Header().Get("Content-Security-Policy"), "form-action 'self';")
	require.NotContains(t, w.Header().Get("Content-Security-Policy"), "script-src")
}

func TestInitial(t *testing.T) {
	cases := map[string]string{
		"Grafana": "G", "  demo app": "D", "élan": "É", "42 Reports": "4", "(beta) Tool": "B", "": "?", "!!!": "?",
	}
	for name, want := range cases {
		require.Equal(t, want, initial(name), name)
	}
}
