package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/modules/twofactor/services"
	"github.com/bete7512/goauth/pkg/config"
)

type TwoFactorHandler struct {
	deps    config.ModuleDependencies
	service *services.TwoFactorService
}

func NewTwoFactorHandler(deps config.ModuleDependencies, service *services.TwoFactorService) *TwoFactorHandler {
	return &TwoFactorHandler{
		deps:    deps,
		service: service,
	}
}

func (h *TwoFactorHandler) GetRoutes() []config.RouteInfo {
	return []config.RouteInfo{
		{
			Name:    "twofactor.setup",
			Path:    "/2fa/setup",
			Method:  "POST",
			Handler: h.Setup,
		},
		{
			Name:    "twofactor.verify",
			Path:    "/2fa/verify",
			Method:  "POST",
			Handler: h.Verify,
		},
		{
			Name:    "twofactor.disable",
			Path:    "/2fa/disable",
			Method:  "POST",
			Handler: h.Disable,
		},
		{
			Name:    "twofactor.status",
			Path:    "/2fa/status",
			Method:  "GET",
			Handler: h.Status,
		},
	}
}

// Setup initiates 2FA setup
func (h *TwoFactorHandler) Setup(w http.ResponseWriter, r *http.Request) {
	// TODO: Get user ID from session/context
	userID := "test-user-id"
	userEmail := "user@example.com"

	// Generate secret
	secret, err := h.service.GenerateSecret()
	if err != nil {
		http.Error(w, "Failed to generate secret", http.StatusInternalServerError)
		return
	}

	// Enable 2FA (initially disabled until verified)
	if err := h.service.EnableTwoFactor(r.Context(), userID, secret); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate QR code URL
	qrURL := h.service.GenerateTOTPURL(userEmail, secret)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"secret":  secret,
		"qr_url":  qrURL,
		"message": "Scan QR code with your authenticator app",
	})
}

// Verify verifies the TOTP code and enables 2FA
func (h *TwoFactorHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// TODO: Get user ID from session/context
	userID := "test-user-id"

	// Verify and enable
	if err := h.service.VerifyAndEnable(r.Context(), userID, req.Code); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Two-factor authentication enabled successfully",
	})
}

// Disable disables 2FA for the user
func (h *TwoFactorHandler) Disable(w http.ResponseWriter, r *http.Request) {
	// TODO: Get user ID from session/context
	userID := "test-user-id"

	if err := h.service.DisableTwoFactor(r.Context(), userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Two-factor authentication disabled",
	})
}

// Status returns 2FA status for the user
func (h *TwoFactorHandler) Status(w http.ResponseWriter, r *http.Request) {
	// TODO: Get user ID from session/context
	userID := "test-user-id"

	status, err := h.service.GetTwoFactorStatus(r.Context(), userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": false,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":  status.Enabled,
		"verified": status.Verified,
		"method":   status.Method,
	})
}
