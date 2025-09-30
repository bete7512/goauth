package auth_handler

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/types"
)

// HandleRegisterWithInvitation handles user registration with invitation token
func (h *AuthHandler) HandleRegisterWithInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
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
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Save user
	response, err := h.services.AuthService.RegisterWithInvitation(r.Context(), &dto.RegisterWithInvitationRequest{
		Email:           req.Email,
		Password:        req.Password,
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		InvitationToken: req.InvitationToken,
	})
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Generate session token
	sessionToken := response.Tokens.AccessToken

	// Save session token
	sessionExpiry := h.config.AuthConfig.JWT.RefreshTokenTTL

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     h.config.AuthConfig.Cookie.Name,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.config.AuthConfig.Cookie.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionExpiry.Seconds()),
	})

	response = &dto.RegisterResponse{
		Message: "registration successful",
		User:    response.User,
	}

	utils.RespondSuccess(w, response.User, "registration successful")
}

// RegisterWithInvitation handles invitation-based registration
func (h *AuthHandler) RegisterWithInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.RegisterWithInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Call service
	response, err := h.services.AuthService.RegisterWithInvitation(r.Context(), &req)
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	if response.Tokens != nil {
		// Set cookies
		// setAuthCookies(w, *response.Tokens)
	}

	utils.RespondSuccess(w, response, "registration successful")
}
