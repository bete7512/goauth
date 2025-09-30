package common_handler

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/bete7512/goauth/pkg/config"
)

type Common struct {
	Auth *config.Auth
}

func NewCommon(auth *config.Auth) *Common {
	return &Common{
		Auth: auth,
	}
}

// setAccessTokenCookie sets a secure access token cookie
func (c *Common) SetAccessTokenCookie(w http.ResponseWriter, accessToken string) {
	cookie := &http.Cookie{
		Name:     "__goauth_access_token_" + c.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Expires:  time.Now().Add(c.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		Domain:   c.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     c.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   c.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: c.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: c.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   int(c.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
	}

	http.SetCookie(w, cookie)
}

func (c *Common) SetRefreshTokenCookie(w http.ResponseWriter, refreshToken string) {
	cookie := &http.Cookie{
		Name:     "___goauth_refresh_token_" + c.Auth.Config.AuthConfig.Cookie.Name,
		Value:    refreshToken,
		Expires:  time.Now().Add(c.Auth.Config.AuthConfig.JWT.RefreshTokenTTL),
		Domain:   c.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     c.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   c.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: c.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: c.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   int(c.Auth.Config.AuthConfig.JWT.RefreshTokenTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}
func (c *Common) SetCsrfTokenCookie(w http.ResponseWriter, csrfToken string) {
	cookie := &http.Cookie{
		Name:     "__goauth_csrf_token_" + c.Auth.Config.Security.CSRF.CookieConfig.Name,
		Value:    csrfToken,
		Expires:  time.Now().Add(c.Auth.Config.Security.CSRF.TokenTTL),
		Domain:   c.Auth.Config.Security.CSRF.CookieConfig.Domain,
		Path:     c.Auth.Config.Security.CSRF.CookieConfig.Path,
		Secure:   c.Auth.Config.Security.CSRF.CookieConfig.Secure,
		HttpOnly: c.Auth.Config.Security.CSRF.CookieConfig.HttpOnly,
		SameSite: c.Auth.Config.Security.CSRF.CookieConfig.SameSite,
		MaxAge:   int(c.Auth.Config.Security.CSRF.TokenTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}

func (c *Common) ClearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "__goauth_access_token_" + c.Auth.Config.AuthConfig.Cookie.Name,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour * 24),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Auth.Config.AuthConfig.Cookie.Secure,
		SameSite: c.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   0,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "__goauth_refresh_token_" + c.Auth.Config.AuthConfig.Cookie.Name,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour * 24),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Auth.Config.AuthConfig.Cookie.Secure,
		SameSite: c.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   0,
	})

}

// validatePasswordPolicy validates a password against the configured policy
func (c *Common) ValidatePasswordPolicy(password string, policy config.PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if policy.RequireUpper && !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if policy.RequireLower && !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if policy.RequireNumber && !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if policy.RequireSpecial && !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

func (c *Common) ValidateEmail(email string) error {
	// RFC 5322 compliant email regex
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

	if !emailRegex.MatchString(email) {
		return errors.New("invalid email address format")
	}
	// Additional checks
	if len(email) > 254 {
		return errors.New("email address too long")
	}
	if len(email) < 5 {
		return errors.New("email address too short")
	}
	if strings.HasSuffix(strings.ToLower(email), "@gmail.com") {
		parts := strings.Split(email, "@")
		localPart := parts[0]
		if strings.Contains(localPart, ".") {
			return errors.New("gmail addresses with dots are not allowed")
		}
	}
	return nil
}

func (c *Common) ValidatePhoneNumber(phoneNumber *string) error {

	//validate phone number
	if c.Auth.Config.AuthConfig.Methods.PhoneVerification.PhoneRequired {
		if phoneNumber == nil {
			return errors.New("phone number is required")
		}
		if *phoneNumber == "" {
			return errors.New("phone number is required")
		}
	}
	// If phone number is not required and is nil, skip validation
	if phoneNumber == nil {
		return nil
	}
	//validate phone number format
	if !regexp.MustCompile(`^\+?[1-9]\d{1,14}$`).MatchString(*phoneNumber) {
		return errors.New("invalid phone number format, example: +1234567890")
	}
	//validate phone number length
	if len(*phoneNumber) < 10 || len(*phoneNumber) > 15 {
		return errors.New("phone number must be between 10 and 15 digits")
	}
	return nil
}

// validateEmailDomain validates email domain against allowed/blocked lists
func (c *Common) ValidateEmailDomain(email string) error {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return errors.New("invalid email format")
	}
	domain := strings.ToLower(parts[1])

	if len(c.Auth.Config.AuthConfig.BlockedEmailDomains) > 0 {
		// Check blocked domains
		for _, blockedDomain := range c.Auth.Config.AuthConfig.BlockedEmailDomains {
			if domain == strings.ToLower(blockedDomain) {
				return fmt.Errorf("email domain %s is not allowed", domain)
			}
		}
	}

	if len(c.Auth.Config.AuthConfig.AllowedEmailDomains) > 0 {
		// Check allowed domains (if configured)
		if len(c.Auth.Config.AuthConfig.AllowedEmailDomains) > 0 {
			allowed := false
			for _, allowedDomain := range c.Auth.Config.AuthConfig.AllowedEmailDomains {
				if domain == strings.ToLower(allowedDomain) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("email domain %s is not in the allowed list", domain)
			}
		}
	}

	return nil
}
