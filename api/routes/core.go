package routes

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/bete7512/goauth/types"
)

type AuthHandler struct {
	Auth *types.Auth
}

// validatePasswordPolicy validates a password against the configured policy
func (h *AuthHandler) validatePasswordPolicy(password string, policy types.PasswordPolicy) error {
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

func (h *AuthHandler) ValidateEmail(email string) error {
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

func (h *AuthHandler) ValidatePhoneNumber(phoneNumber *string) error {

	//validate phone number
	if h.Auth.Config.AuthConfig.PhoneNumberRequired {
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

// authenticateRequest extracts and validates the token from a request
func (h *AuthHandler) authenticateRequest(r *http.Request, cookieName, jwtSecret string) (string, error) {
	token := h.extractToken(r, cookieName)
	if token == "" {
		return "", errors.New("no authentication token provided")
	}

	claims, err := h.Auth.TokenManager.ValidateJWTToken(token)
	if err != nil {
		return "", err
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return userID, nil
}

func (h *AuthHandler) extractToken(r *http.Request, cookieName string) string {
	if cookieName != "" {
		cookie, err := r.Cookie("___goauth_access_token_" + cookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}
	if h.Auth.Config.AuthConfig.EnableBearerAuth {
		bearerToken := r.Header.Get("Authorization")
		if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
			return bearerToken[7:]
		}

	}

	return ""
}
