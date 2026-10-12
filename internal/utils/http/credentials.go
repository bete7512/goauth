package http_utils

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/types"
)

func CookiesEnabled(mode types.AuthMode) bool {
	return mode == "" || mode == types.AuthModeCookie || mode == types.AuthModeBoth
}

// RefreshCredential applies the same transport rules across credential
// strategies. A JSON refresh_token is a bearer credential; cookie-only clients
// must send their refresh cookie. Conflicting enabled inputs are rejected.
func RefreshCredential(r *http.Request, cfg types.SecurityConfig, body string) (string, error) {
	var values []string
	if CookiesEnabled(cfg.AuthMode) {
		if c, err := r.Cookie("goauth_refresh_" + cfg.Session.Name); err == nil {
			values = append(values, c.Value)
		}
	}
	if cfg.AuthMode != types.AuthModeCookie {
		values = append(values, body)
		header := r.Header.Get("Authorization")
		if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
			values = append(values, header[7:])
		}
	}
	var token string
	for _, value := range values {
		if value == "" {
			continue
		}
		if token != "" && token != value {
			return "", fmt.Errorf("conflicting refresh credentials")
		}
		token = value
	}
	return token, nil
}

// SetCredentialCookies is the common transport policy for every authenticator.
func SetCredentialCookies(w http.ResponseWriter, cfg types.SecurityConfig, access, refresh string) {
	if !CookiesEnabled(cfg.AuthMode) {
		return
	}
	for _, value := range []struct {
		name, token string
		ttl         time.Duration
	}{
		{"access", access, cfg.Session.AccessTokenTTL},
		{"refresh", refresh, cfg.Session.RefreshTokenTTL},
	} {
		if value.token == "" {
			continue
		}
		http.SetCookie(w, credentialCookie(cfg.Session, value.name, value.token, int(value.ttl.Seconds())))
	}
}

func ClearCredentialCookies(w http.ResponseWriter, cfg types.SecurityConfig) {
	for _, name := range []string{"access", "refresh", "session"} {
		http.SetCookie(w, credentialCookie(cfg.Session, name, "", -1))
	}
}

func credentialCookie(cfg types.SessionConfig, purpose, value string, age int) *http.Cookie {
	return &http.Cookie{Name: "goauth_" + purpose + "_" + cfg.Name, Value: value, HttpOnly: true,
		Secure: cfg.Secure, SameSite: cfg.SameSite, Path: cfg.Path, Domain: cfg.Domain, MaxAge: age}
}

// AccessCredential rejects conflicting credentials instead of choosing an
// identity based on transport precedence. Identical credentials are harmless.
func AccessCredential(r *http.Request, cfg types.SecurityConfig) string {
	var cookie, bearer string
	if CookiesEnabled(cfg.AuthMode) {
		if c, err := r.Cookie("goauth_access_" + cfg.Session.Name); err == nil {
			cookie = c.Value
		}
	}
	if cfg.AuthMode == "" || cfg.AuthMode == types.AuthModeBoth || cfg.AuthMode == types.AuthModeBearer {
		header := r.Header.Get("Authorization")
		if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
			bearer = header[7:]
		}
	}
	if cookie != "" && bearer != "" && cookie != bearer {
		return ""
	}
	if bearer != "" {
		return bearer
	}
	return cookie
}
