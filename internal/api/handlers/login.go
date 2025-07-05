package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/dto"
)

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
	// setAuthCookies(w, response.Tokens)

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleLogin handles user login
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
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
	// setAuthCookies(w, response.Tokens)
	if h.Auth.Config.AuthConfig.Methods.Type == config.AuthenticationTypeCookie {
		// setAuthCookies(w, response.Tokens)
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}
