package auth_handler

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/types"
)

// Register handles user registration
func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.RegisterRequest
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
	response, err := h.services.AuthService.Register(r.Context(), &req)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), err.Error())
		return
	}
	if h.config.AuthConfig.Methods.EmailVerification.EnableOnSignup {
		response.Tokens = nil
	}

	utils.RespondSuccess(w, response, "User registered successfully")
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.LoginRequest
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
	response, err := h.services.AuthService.Login(r.Context(), &req)
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Set cookies
	// setAuthCookies(w, response.Tokens)

	utils.RespondSuccess(w, response, "Login successful")
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	// Parse and validate request
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	if err := req.Validate(); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Call service
	response, err := h.services.AuthService.Login(r.Context(), &req)
	if err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	// Convert to response format
	loginResponse := dto.LoginResponse{
		User:         response.User,
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		ExpiresIn:    response.ExpiresIn,
		TokenType:    response.TokenType,
	}

	utils.RespondSuccess[dto.LoginResponse](w, loginResponse, "Login successful")
}

// HandleLogout handles user logout
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)
	sessionID := r.Context().Value("session_id").(string)

	// Call service
	if err := h.services.AuthService.Logout(r.Context(), userID, sessionID); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	h.common.ClearAuthCookies(w)

	utils.RespondSuccess[any](w, nil, "logout successful")

}

// ForgotPassword handles password reset request
func (h *AuthHandler) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.ForgotPasswordRequest
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
	if err := h.services.AuthService.ForgotPassword(r.Context(), &req); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "failed to process request")
		return
	}

	utils.RespondSuccess[any](w, nil, "password reset email sent")

}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)
	sessionID := r.Context().Value("session_id").(string)

	// Call service
	if err := h.services.AuthService.Logout(r.Context(), userID, sessionID); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "logout failed")
		return
	}

	h.common.ClearAuthCookies(w)

	utils.RespondSuccess[any](w, nil, "logout successful")
}
