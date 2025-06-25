package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	responseErrors "github.com/bete7512/goauth/internal/api/handlers/errors"
	"github.com/bete7512/goauth/internal/schemas"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
)

// HandleLogin handles user login
func (h *AuthRoutes) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}
	// ip := utils.GetIpFromRequest(r)
	var req schemas.LoginRequest
	// Then your hook can access both
	if h.Auth.HookManager.GetAfterHook(config.RouteLogin) != nil {
		var rawData map[string]interface{}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "failed to read request body: "+err.Error(), nil)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := json.Unmarshal(bodyBytes, &rawData); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid request body json: "+err.Error(), nil)
			return
		}
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid request format: "+err.Error(), nil)
			return
		}
		ctx := context.WithValue(r.Context(), config.RequestDataKey, rawData)
		r = r.WithContext(ctx)
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), nil)
			return
		}
	}

	// // check for recaptcha if enabled
	// if h.Auth.Config.Security.Recaptcha.Enabled && h.Auth.Config.Security.Recaptcha.Routes[config.RouteLogin] {
	// 	if req.RecaptchaToken == "" {
	// 		utils.RespondWithError(w, http.StatusBadRequest, "recaptcha token is required", nil)
	// 		return
	// 	}
	// 	ok, err := h.Auth.RecaptchaManager.Verify(r.Context(), req.RecaptchaToken, ip) // TODO: add recaptcha manager to test auth handler
	// 	if err != nil {
	// 		utils.RespondWithError(w, http.StatusInternalServerError, "recaptcha verification failed: "+err.Error(), nil)
	// 		return
	// 	}
	// 	if !ok {
	// 		utils.RespondWithError(w, http.StatusBadRequest, "recaptcha verification failed", nil)
	// 		return
	// 	}
	// }

	// Get user by email
	user, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if err.Error() == "user not found" {
			utils.RespondWithError(w, http.StatusUnauthorized, "user not found", nil)
			return
		}
		utils.RespondWithError(w, http.StatusUnauthorized, "invalid email or password", err)
		return
	}
	if user == nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "user not found", nil)
		return
	}
	if user.Active == nil || !*user.Active {
		utils.RespondWithError(w, http.StatusUnauthorized, responseErrors.ErrUserNotActive, nil)
		return
	}

	err = h.Auth.TokenManager.ValidatePassword(user.Password, req.Password)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "invalid email or password", err)
		return
	}

	// Handle two-factor authentication if enabled
	if h.Auth.Config.AuthConfig.Methods.EnableTwoFactor && user.TwoFactorEnabled != nil && *user.TwoFactorEnabled {
		if req.TwoFactorCode == "" {
			err = h.sendTwoFactorCode(r.Context(), user)
			if err != nil {
				utils.RespondWithError(w, http.StatusInternalServerError, "failed to send two-factor code", nil)
				return
			}
			err := utils.RespondWithJSON(
				w,
				http.StatusOK,
				map[string]interface{}{
					"message":      "two-factor code sent",
					"requires_2fa": true,
					// "two_factor_method": user.TwoFactorEnabled,
				},
			)
			if err != nil {
				utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", nil)
				return
			}
			return
		} else {
			twoFactorTTl := 10 * time.Minute
			err = h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), user.ID, req.TwoFactorCode, models.TwoFactorCode, twoFactorTTl)
			if err != nil {
				utils.RespondWithError(w, http.StatusUnauthorized, "invalid two-factor code", nil)
				return
			}
		}
	}

	accessToken, refreshToken, err := h.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to generate authentication tokens", nil)
		return
	}

	deviceIdToken, err := h.Auth.TokenManager.GenerateBase64Token(24)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to generate device id token", nil)
		return
	}
	// Save refresh token
	err = h.Auth.Repository.GetTokenRepository().SaveTokenWithDeviceId(r.Context(), user.ID, refreshToken, deviceIdToken, models.RefreshToken, h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to save refresh token", nil)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_access_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    accessToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_refresh_token_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    refreshToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "___goauth_device_id_" + h.Auth.Config.AuthConfig.Cookie.Name,
		Value:    deviceIdToken,
		Expires:  time.Now().Add(h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL),
		Domain:   h.Auth.Config.AuthConfig.Cookie.Domain,
		Path:     h.Auth.Config.AuthConfig.Cookie.Path,
		Secure:   h.Auth.Config.AuthConfig.Cookie.Secure,
		HttpOnly: h.Auth.Config.AuthConfig.Cookie.HttpOnly,
		SameSite: h.Auth.Config.AuthConfig.Cookie.SameSite,
		MaxAge:   h.Auth.Config.AuthConfig.Cookie.MaxAge,
	})
	if h.Auth.HookManager.GetAfterHook(config.RouteLogin) != nil {

		ctx := context.WithValue(r.Context(), config.ResponseDataKey, map[string]interface{}{
			"id":            user.ID,
			"user":          user,
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(config.RouteLogin, w, r)
	} else {
		userResponse := schemas.UserResponse{
			ID:        user.ID,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
		}
		// Send response
		response := map[string]interface{}{
			"user":          userResponse,
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		}
		err := utils.RespondWithJSON(w, http.StatusOK, response)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", nil)
			return
		}
	}

}
