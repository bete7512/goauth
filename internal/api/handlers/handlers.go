package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/services"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// AuthHandler handles HTTP requests for authentication
type AuthHandler struct {
	Auth        *config.Auth
	authService interfaces.Service
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(auth *config.Auth) *AuthHandler {
	service := services.NewAuthService(auth)
	return &AuthHandler{
		authService: service,
		Auth:        auth,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	response, err := h.authService.Register(r.Context(), &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	// Set cookies if tokens are provided
	if response.Tokens.AccessToken != "" {
		setAuthCookies(w, response.Tokens)
	}

	utils.RespondWithJSON(w, http.StatusCreated, response)
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	response, err := h.authService.Login(r.Context(), &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, err.Error(), err)
		return
	}

	// Set cookies
	setAuthCookies(w, response.Tokens)

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.authService.Logout(r.Context(), userID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "logout failed", err)
		return
	}

	// Clear cookies
	clearAuthCookies(w)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "logout successful"})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Call service
	response, err := h.authService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, err.Error(), err)
		return
	}

	// Set new cookies
	setAuthCookies(w, response.Tokens)

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// ForgotPassword handles password reset request
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	if err := h.authService.ForgotPassword(r.Context(), &req); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to process request", err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "password reset email sent"})
}

// ResetPassword handles password reset
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	if err := h.authService.ResetPassword(r.Context(), &req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "password reset successful"})
}

// SendMagicLink handles magic link request
func (h *AuthHandler) SendMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.MagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	if err := h.authService.SendMagicLink(r.Context(), &req); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send magic link", err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "magic link sent"})
}

// VerifyMagicLink handles magic link verification
func (h *AuthHandler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.MagicLinkVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	response, err := h.authService.VerifyMagicLink(r.Context(), &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Set cookies
	setAuthCookies(w, response.Tokens)

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// RegisterWithInvitation handles invitation-based registration
func (h *AuthHandler) RegisterWithInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.RegisterWithInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Call service
	response, err := h.authService.RegisterWithInvitation(r.Context(), &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Set cookies
	setAuthCookies(w, response.Tokens)

	utils.RespondWithJSON(w, http.StatusCreated, response)
}

// Helper functions for cookie management
func setAuthCookies(w http.ResponseWriter, tokens dto.TokenData) {
	// Set access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(tokens.ExpiresAt.Unix()),
	})

	// Set refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   30 * 24 * 60 * 60, // 30 days
	})
}

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
