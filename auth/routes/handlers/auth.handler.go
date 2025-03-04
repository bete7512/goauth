// auth/routes/handlers/auth_handler.go
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/go-auth/auth/models"
	"github.com/bete7512/go-auth/auth/schemas"
	"github.com/bete7512/go-auth/auth/types"
	"github.com/bete7512/go-auth/auth/utils"
)

type AuthHandler struct {
	Auth *types.Auth
}

func New(config *types.Auth) *AuthHandler {
	return &AuthHandler{Auth: config}
}

// WithHooks wraps a handler function with before and after hooks
func (h *AuthHandler) WithHooks(route string, handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Execute before hooks
		if h.Auth.HookManager != nil {
			if !h.Auth.HookManager.ExecuteBeforeHooks(route, w, r) {
				return
			}
		}
		handler(w, r)
		// Execute after hooks
		if h.Auth.HookManager != nil {
			h.Auth.HookManager.ExecuteAfterHooks(route, w, r)
		}
	}
}

func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req schemas.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user := models.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
	}
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user.Password = hashedPassword
	err = h.Auth.Repository.GetUserRepository().CreateUser(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"user":          user,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req schemas.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = utils.ValidatePassword(user.Password, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"user":          user,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// // HandleLogout implements logout functionality
// func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Invalidate token logic would go here
// 	// Typically involves blacklisting the token or setting cookies to expire

// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
// }

// // HandleRefreshToken implements token refresh functionality
// func (h *AuthHandler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var req schemas.RefreshTokenRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Validate refresh token and generate new tokens
// 	userId, err := utils.ValidateToken(req.RefreshToken, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
// 		return
// 	}

// 	accessToken, refreshToken, err := utils.GenerateTokens(userId, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	response := map[string]string{
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(response)
// }




// Additional handlers for forgot password, reset password, etc. would follow...
// package handlers

// import (
// 	"encoding/json"
// 	"net/http"

// 	"github.com/bete7512/go-auth/auth/models"
// 	"github.com/bete7512/go-auth/auth/schemas"
// 	"github.com/bete7512/go-auth/auth/types"
// 	"github.com/bete7512/go-auth/auth/utils"
// )

// type AuthHandler struct {
// 	Auth *types.Auth
// }

// func New(config *types.Auth) *AuthHandler {
// 	return &AuthHandler{Auth: config}
// }

// func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var req schemas.RegisterRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	user := models.User{
// 		FirstName: req.FirstName,
// 		LastName:  req.LastName,
// 		Email:     req.Email,
// 	}
// 	hashedPassword, err := utils.HashPassword(req.Password)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	user.Password = hashedPassword
// 	err = h.Auth.Repository.GetUserRepository().CreateUser(&user)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"user":          user,
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusCreated)
// 	if err := json.NewEncoder(w).Encode(response); err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// }

// func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	var req schemas.LoginRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(req.Email)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	err = utils.ValidatePassword(user.Password, req.Password)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	accessToken, refreshToken, err := utils.GenerateTokens(user.ID, h.Auth.Config.AccessTokenTTL, h.Auth.Config.JWTSecret)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	response := map[string]interface{}{
// 		"user":          user,
// 		"access_token":  accessToken,
// 		"refresh_token": refreshToken,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusCreated)
// 	if err := json.NewEncoder(w).Encode(response); err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// }
// // TODO: continue working
// // logout
// // refresh token
// // forgot password
// // reset password
// // update user
// // delete user
// // get user
