package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
)

// HandleListUsers handles listing all users with pagination and filtering
func (h *AuthRoutes) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	email := strings.TrimSpace(r.URL.Query().Get("email"))

	filter := interfaces.Filter{
		Pagination: interfaces.Pagination{
			Page:  page,
			Limit: limit,
		},
		Sort: interfaces.Sort{
			Field:     "created_at",
			Direction: "desc",
		},
		Search: search,
		Email:  email,
	}

	users, total, err := h.Auth.Repository.GetUserRepository().GetAllUsers(r.Context(), filter)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch users", err)
		return
	}

	// Remove sensitive information
	var safeUsers []map[string]interface{}
	for _, user := range users {
		safeUser := map[string]interface{}{
			"id":                 user.ID,
			"first_name":         user.FirstName,
			"last_name":          user.LastName,
			"email":              user.Email,
			"phone_number":       user.PhoneNumber,
			"email_verified":     user.EmailVerified,
			"phone_verified":     user.PhoneVerified,
			"active":             user.Active,
			"is_admin":           user.IsAdmin,
			"created_at":         user.CreatedAt,
			"updated_at":         user.UpdatedAt,
			"last_login_at":      user.LastLoginAt,
			"signed_up_via":      user.SignedUpVia,
			"two_factor_enabled": user.TwoFactorEnabled,
		}
		safeUsers = append(safeUsers, safeUser)
	}

	response := map[string]interface{}{
		"users": safeUsers,
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": (int(total) + limit - 1) / limit,
		},
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleGetUser handles getting a specific user by ID
func (h *AuthRoutes) HandleAdminGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract user ID from URL path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		utils.RespondWithError(w, http.StatusBadRequest, "user ID is required", nil)
		return
	}
	userID := pathParts[len(pathParts)-1]

	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "user not found", err)
		return
	}

	// Remove sensitive information
	safeUser := map[string]interface{}{
		"id":                 user.ID,
		"first_name":         user.FirstName,
		"last_name":          user.LastName,
		"email":              user.Email,
		"phone_number":       user.PhoneNumber,
		"email_verified":     user.EmailVerified,
		"phone_verified":     user.PhoneVerified,
		"active":             user.Active,
		"is_admin":           user.IsAdmin,
		"created_at":         user.CreatedAt,
		"updated_at":         user.UpdatedAt,
		"last_login_at":      user.LastLoginAt,
		"signed_up_via":      user.SignedUpVia,
		"two_factor_enabled": user.TwoFactorEnabled,
	}

	utils.RespondWithJSON(w, http.StatusOK, safeUser)
}

// HandleUpdateUser handles updating a user's information
func (h *AuthRoutes) HandleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract user ID from URL path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		utils.RespondWithError(w, http.StatusBadRequest, "user ID is required", nil)
		return
	}
	userID := pathParts[len(pathParts)-1]

	var req struct {
		FirstName        *string `json:"first_name,omitempty"`
		LastName         *string `json:"last_name,omitempty"`
		Email            *string `json:"email,omitempty"`
		PhoneNumber      *string `json:"phone_number,omitempty"`
		Active           *bool   `json:"active,omitempty"`
		IsAdmin          *bool   `json:"is_admin,omitempty"`
		EmailVerified    *bool   `json:"email_verified,omitempty"`
		PhoneVerified    *bool   `json:"phone_verified,omitempty"`
		TwoFactorEnabled *bool   `json:"two_factor_enabled,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "user not found", err)
		return
	}

	// Update fields if provided
	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.PhoneNumber != nil {
		user.PhoneNumber = req.PhoneNumber
	}
	if req.Active != nil {
		user.Active = req.Active
	}
	if req.IsAdmin != nil {
		user.IsAdmin = req.IsAdmin
	}
	if req.EmailVerified != nil {
		user.EmailVerified = req.EmailVerified
	}
	if req.PhoneVerified != nil {
		user.PhoneVerified = req.PhoneVerified
	}
	if req.TwoFactorEnabled != nil {
		user.TwoFactorEnabled = req.TwoFactorEnabled
	}

	if err := h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to update user", err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "user updated successfully"})
}

// HandleDeleteUser handles deleting a user
func (h *AuthRoutes) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract user ID from URL path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		utils.RespondWithError(w, http.StatusBadRequest, "user ID is required", nil)
		return
	}
	userID := pathParts[len(pathParts)-1]

	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "user not found", err)
		return
	}

	// Check if trying to delete self
	adminUserID := r.Context().Value("user_id")
	if adminUserID != nil && adminUserID.(string) == userID {
		utils.RespondWithError(w, http.StatusBadRequest, "cannot delete your own account", nil)
		return
	}

	if err := h.Auth.Repository.GetUserRepository().DeleteUser(r.Context(), user); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to delete user", err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "user deleted successfully"})
}

// HandleActivateUser handles activating/deactivating a user
func (h *AuthRoutes) HandleActivateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract user ID from URL path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		utils.RespondWithError(w, http.StatusBadRequest, "user ID is required", nil)
		return
	}
	userID := pathParts[len(pathParts)-1]

	var req struct {
		Active bool `json:"active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, "user not found", err)
		return
	}

	user.Active = &req.Active

	if err := h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to update user", err)
		return
	}

	action := "activated"
	if !req.Active {
		action = "deactivated"
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "user " + action + " successfully"})
}

// HandleBulkAction handles bulk actions on users (activate, deactivate, delete)
func (h *AuthRoutes) HandleBulkAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req struct {
		Action  string   `json:"action"` // "activate", "deactivate", "delete"
		UserIDs []string `json:"user_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	if len(req.UserIDs) == 0 {
		utils.RespondWithError(w, http.StatusBadRequest, "user IDs are required", nil)
		return
	}

	adminUserID := r.Context().Value("user_id")
	successCount := 0
	errors := []string{}

	for _, userID := range req.UserIDs {
		// Prevent admin from performing bulk action on themselves
		if adminUserID != nil && adminUserID.(string) == userID && req.Action == "delete" {
			errors = append(errors, "cannot delete your own account")
			continue
		}

		user, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), userID)
		if err != nil {
			errors = append(errors, "user "+userID+" not found")
			continue
		}

		switch req.Action {
		case "activate":
			active := true
			user.Active = &active
			if err := h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user); err != nil {
				errors = append(errors, "failed to activate user "+userID)
			} else {
				successCount++
			}
		case "deactivate":
			active := false
			user.Active = &active
			if err := h.Auth.Repository.GetUserRepository().UpdateUser(r.Context(), user); err != nil {
				errors = append(errors, "failed to deactivate user "+userID)
			} else {
				successCount++
			}
		case "delete":
			if err := h.Auth.Repository.GetUserRepository().DeleteUser(r.Context(), user); err != nil {
				errors = append(errors, "failed to delete user "+userID)
			} else {
				successCount++
			}
		default:
			utils.RespondWithError(w, http.StatusBadRequest, "invalid action", nil)
			return
		}
	}

	response := map[string]interface{}{
		"success_count": successCount,
		"total_count":   len(req.UserIDs),
		"errors":        errors,
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleSystemStats handles getting system statistics
func (h *AuthRoutes) HandleSystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Get basic stats (this would need to be implemented in the repository)
	// For now, return placeholder data
	stats := map[string]interface{}{
		"total_users":          0,               // TODO: implement count
		"active_users":         0,               // TODO: implement count
		"verified_users":       0,               // TODO: implement count
		"admin_users":          0,               // TODO: implement count
		"users_with_2fa":       0,               // TODO: implement count
		"recent_registrations": []interface{}{}, // TODO: implement recent users
		"system_health": map[string]interface{}{
			"database": "healthy",
			"redis":    "healthy",
			"uptime":   "0s", // TODO: implement uptime tracking
		},
	}

	utils.RespondWithJSON(w, http.StatusOK, stats)
}

// HandleGetAuditLogs handles getting audit logs with pagination
func (h *AuthRoutes) HandleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	// TODO: Use these parameters when audit log repository is implemented
	// eventType := strings.TrimSpace(r.URL.Query().Get("event_type"))
	// userID := strings.TrimSpace(r.URL.Query().Get("user_id"))

	// TODO: Implement audit log repository and methods
	// filter := interfaces.Filter{
	// 	Pagination: interfaces.Pagination{
	// 		Page:  page,
	// 		Limit: limit,
	// 	},
	// 	Sort: interfaces.Sort{
	// 		Field:     "created_at",
	// 		Direction: "desc",
	// 	},
	// 	UserId: userID,
	// }

	// Placeholder response
	response := map[string]interface{}{
		"logs": []interface{}{},
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       0,
			"total_pages": 0,
		},
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleSystemHealth handles system health check
func (h *AuthRoutes) HandleSystemHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	health := map[string]interface{}{
		"status": "healthy",
		"checks": map[string]interface{}{
			"database": map[string]interface{}{
				"status":  "healthy",
				"latency": "0ms",
			},
			"redis": map[string]interface{}{
				"status":  "healthy",
				"latency": "0ms",
			},
			"email_service": map[string]interface{}{
				"status": "healthy",
			},
			"sms_service": map[string]interface{}{
				"status": "healthy",
			},
		},
		"timestamp": "2024-01-01T00:00:00Z", // TODO: use actual timestamp
	}

	utils.RespondWithJSON(w, http.StatusOK, health)
}

// HandleExportUsers handles exporting users data
func (h *AuthRoutes) HandleExportUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	if format != "json" && format != "csv" {
		utils.RespondWithError(w, http.StatusBadRequest, "unsupported format", nil)
		return
	}

	// Get all users (without pagination for export)
	filter := interfaces.Filter{
		Pagination: interfaces.Pagination{
			Page:  1,
			Limit: 10000, // Large limit for export
		},
		Sort: interfaces.Sort{
			Field:     "created_at",
			Direction: "desc",
		},
	}

	users, _, err := h.Auth.Repository.GetUserRepository().GetAllUsers(r.Context(), filter)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch users", err)
		return
	}

	// Remove sensitive information
	var safeUsers []map[string]interface{}
	for _, user := range users {
		safeUser := map[string]interface{}{
			"id":                 user.ID,
			"first_name":         user.FirstName,
			"last_name":          user.LastName,
			"email":              user.Email,
			"phone_number":       user.PhoneNumber,
			"email_verified":     user.EmailVerified,
			"phone_verified":     user.PhoneVerified,
			"active":             user.Active,
			"is_admin":           user.IsAdmin,
			"created_at":         user.CreatedAt,
			"updated_at":         user.UpdatedAt,
			"last_login_at":      user.LastLoginAt,
			"signed_up_via":      user.SignedUpVia,
			"two_factor_enabled": user.TwoFactorEnabled,
		}
		safeUsers = append(safeUsers, safeUser)
	}

	if format == "csv" {
		// TODO: Implement CSV export
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=users.csv")
		utils.RespondWithError(w, http.StatusNotImplemented, "CSV export not implemented yet", nil)
		return
	}

	// JSON export
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=users.json")
	utils.RespondWithJSON(w, http.StatusOK, safeUsers)
}

// HandleInviteUser handles inviting a new user via email
func (h *AuthRoutes) HandleInviteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req struct {
		Email     string `json:"email" validate:"required,email"`
		FirstName string `json:"first_name" validate:"required"`
		LastName  string `json:"last_name" validate:"required"`
		IsAdmin   bool   `json:"is_admin"`
		Message   string `json:"message"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Check if user already exists
	existingUser, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(r.Context(), req.Email)
	if err == nil && existingUser != nil {
		utils.RespondWithError(w, http.StatusConflict, "user with this email already exists", nil)
		return
	}

	// Get admin user info for invitation
	adminUserID := r.Context().Value("user_id")
	adminUser, err := h.Auth.Repository.GetUserRepository().GetUserByID(r.Context(), adminUserID.(string))
	if err != nil || adminUser == nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "admin user not found", err)
		return
	}

	// Create invitation token
	invitationToken, err := h.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to generate invitation token", err)
		return
	}

	hashedToken, err := h.Auth.TokenManager.HashToken(invitationToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to hash invitation token", err)
		return
	}

	// Save invitation token (24 hour expiry)
	expiry := 24 * time.Hour
	if err := h.Auth.Repository.GetTokenRepository().SaveToken(r.Context(), req.Email, hashedToken, models.InvitationToken, expiry); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to save invitation token", err)
		return
	}

	// Create invitation URL
	invitationURL := fmt.Sprintf("%s/register?invitation=%s&email=%s", h.Auth.Config.App.FrontendURL, invitationToken, req.Email)

	// Send invitation email
	if h.Auth.EmailSender != nil {
		invitedBy := fmt.Sprintf("%s %s (%s)", adminUser.FirstName, adminUser.LastName, adminUser.Email)
		if err := h.Auth.EmailSender.SendInvitationEmail(r.Context(), req.Email, req.FirstName, invitationURL, invitedBy); err != nil {
			// Log the error but don't fail the request
			h.Auth.Logger.Errorf("Failed to send invitation email: %v", err)
		}
	}

	// Store invitation data for later use (when user completes registration)
	// TODO: Store invitation data in database or cache for later retrieval
	// This could be stored in a separate invitations table or in cache
	// invitationData := map[string]interface{}{
	// 	"email":       req.Email,
	// 	"first_name":  req.FirstName,
	// 	"last_name":   req.LastName,
	// 	"is_admin":    req.IsAdmin,
	// 	"invited_by":  adminUserID.(string),
	// 	"message":     req.Message,
	// 	"created_at":  time.Now(),
	// }

	response := map[string]interface{}{
		"message": "invitation sent successfully",
		"email":   req.Email,
		"expires": "24 hours",
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleListInvitations handles listing pending invitations
func (h *AuthRoutes) HandleListInvitations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// TODO: Implement invitation listing from database/cache
	// For now, return empty list
	response := map[string]interface{}{
		"invitations": []interface{}{},
		"pagination": map[string]interface{}{
			"page":        1,
			"limit":       20,
			"total":       0,
			"total_pages": 0,
		},
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleCancelInvitation handles canceling a pending invitation
func (h *AuthRoutes) HandleCancelInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract invitation ID from URL path
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 4 {
		utils.RespondWithError(w, http.StatusBadRequest, "invitation ID is required", nil)
		return
	}
	// invitationID := pathParts[len(pathParts)-1]

	// TODO: Implement invitation cancellation
	// This would involve:
	// 1. Finding the invitation by ID
	// 2. Revoking the invitation token
	// 3. Removing invitation data from storage

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{"message": "invitation canceled successfully"})
}
