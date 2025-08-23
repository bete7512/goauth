package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
)

// HandleRegisterWithInvitation handles user registration with invitation token
func (h *AuthHandler) HandleRegisterWithInvitation(w http.ResponseWriter, r *http.Request) {
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

	// hashedSessionToken, err := h.Auth.TokenManager.HashToken(sessionToken)
	// if err != nil {
	// 	utils.RespondWithError(w, http.StatusInternalServerError, "failed to hash session token", err)
	// 	return
	// }

	// Save session token
	sessionExpiry := h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL
	// if err := h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, hashedSessionToken, models.RefreshToken, sessionExpiry); err != nil {
	// 	utils.RespondWithError(w, http.StatusInternalServerError, "failed to save session token", err)
	// 	return
	// }

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
	if h.Auth.Config.Email.CustomSender != nil {
		if err := h.Auth.Config.Email.CustomSender.SendWelcomeEmail(r.Context(), *user); err != nil {
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

	if response.Tokens != nil {
		// Set cookies
		// setAuthCookies(w, *response.Tokens)
	}

	utils.RespondWithJSON(w, http.StatusCreated, response)
}
