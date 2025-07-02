package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
)

type AuthRoutes struct {
	*config.Auth
}

func NewAuthRoutes(auth *config.Auth) *AuthRoutes {
	return &AuthRoutes{
		Auth: auth,
	}
}

// authenticateRequest extracts and validates the token from a request
func (h *AuthRoutes) authenticateRequest(r *http.Request, cookieName, jwtSecret string) (string, error) {
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

func (h *AuthRoutes) extractToken(r *http.Request, cookieName string) string {
	if cookieName != "" {
		cookie, err := r.Cookie("___goauth_access_token_" + cookieName)
		if err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}
	// Check for bearer token (assuming it's enabled by default for testing)
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}

	return ""
}

// setAccessTokenCookie sets a secure access token cookie
func (h *AuthRoutes) setAccessTokenCookie(w http.ResponseWriter, accessToken string) {
	cookie := &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.Auth.Config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
	}

	http.SetCookie(w, cookie)
}

func (h *AuthRoutes) setRefreshTokenCookie(w http.ResponseWriter, refreshToken string) {
	cookie := &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    refreshToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}
func (h *AuthRoutes) setCsrfTokenCookie(w http.ResponseWriter, csrfToken string) {
	cookie := &http.Cookie{
		Name:  "___goauth_csrf_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value: csrfToken,
		// Expires:  time.Now().Add(h.Auth.Config.AuthConfig.CSRF.TTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: http.SameSiteStrictMode,
		// MaxAge:   int(h.Auth.Config.AuthConfig.CSRF.TTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}

// HandleRegisterWithInvitation handles user registration with invitation token
func (h *AuthRoutes) HandleRegisterWithInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req struct {
		Email           string `json:"email" validate:"required,email"`
		Password        string `json:"password" validate:"required,min=8"`
		FirstName       string `json:"first_name" validate:"required"`
		LastName        string `json:"last_name" validate:"required"`
		InvitationToken string `json:"invitation_token" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// TODO: Validate invitation token
	// For now, we'll trust the invitation token from the frontend
	// In a real implementation, you would validate the token against the database

	// Check if user already exists
	existingUser, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(r.Context(), req.Email)
	if err == nil && existingUser != nil {
		utils.RespondWithError(w, http.StatusConflict, "user with this email already exists", nil)
		return
	}

	// Hash password
	hashedPassword, err := h.Auth.TokenManager.HashPassword(req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to hash password", err)
		return
	}

	// Create user
	emailVerified := true
	active := true
	isAdmin := false
	user := &models.User{
		Email:         req.Email,
		Password:      hashedPassword,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Active:        &active,
		EmailVerified: &emailVerified,
		IsAdmin:       &isAdmin,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Save user
	if err := h.Auth.Repository.GetUserRepository().CreateUser(r.Context(), user); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to create user", err)
		return
	}

	// Revoke invitation token after successful registration
	h.Auth.Repository.GetTokenRepository().RevokeAllTokens(r.Context(), req.Email, models.InvitationToken)

	// Generate session token
	sessionToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to generate session token", err)
		return
	}

	hashedSessionToken, err := h.Auth.TokenManager.HashToken(sessionToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to hash session token", err)
		return
	}

	// Save session token
	sessionExpiry := h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL
	if err := h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, hashedSessionToken, models.RefreshToken, sessionExpiry); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to save session token", err)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionExpiry.Seconds()),
	})

	// Send welcome email
	if h.Auth.EmailSender != nil {
		if err := h.Auth.EmailSender.SendWelcomeEmail(r.Context(), *user); err != nil {
			// Log the error but don't fail the request
			h.Auth.Logger.Errorf("Failed to send welcome email: %v", err)
		}
	}

	response := map[string]interface{}{
		"message": "registration successful",
		"user": map[string]interface{}{
			"id":         user.ID,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"active":     user.Active,
			"is_admin":   user.IsAdmin,
		},
	}

	utils.RespondWithJSON(w, http.StatusCreated, response)
}
