package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
)

// HandleListUsers handles listing users for admin
func (h *AuthHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
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
	if limit <= 0 {
		limit = 10
	}
	sortBy := r.URL.Query().Get("sort_by")
	if sortBy == "" {
		sortBy = "created_at"
	}
	sortDir := r.URL.Query().Get("sort_dir")
	if sortDir == "" {
		sortDir = "desc"
	}
	search := r.URL.Query().Get("search")

	req := &dto.ListUsersRequest{
		Page:    page,
		Limit:   limit,
		SortBy:  sortBy,
		SortDir: sortDir,
		Search:  search,
	}

	// Call service
	response, err := h.authService.ListUsers(r.Context(), req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleGetUser handles getting a specific user for admin
func (h *AuthHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract user ID from URL path
	userID := r.URL.Query().Get("id")
	if userID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "user ID is required", nil)
		return
	}

	// Call service
	response, err := h.authService.GetUser(r.Context(), userID)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleUpdateUser handles updating a user for admin
func (h *AuthHandler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract user ID from URL path
	userID := r.URL.Query().Get("id")
	if userID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "user ID is required", nil)
		return
	}

	var req dto.AdminUpdateUserRequest
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
	response, err := h.authService.UpdateUser(r.Context(), userID, &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleDeleteUser handles deleting a user for admin
func (h *AuthHandler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract user ID from URL path
	userID := r.URL.Query().Get("id")
	if userID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "user ID is required", nil)
		return
	}

	// Call service
	if err := h.authService.DeleteUser(r.Context(), userID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "user deleted successfully"})
}

// HandleActivateUser handles activating a user for admin
func (h *AuthHandler) HandleActivateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract user ID from URL path
	userID := r.URL.Query().Get("id")
	if userID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "user ID is required", nil)
		return
	}

	// Call service
	if err := h.authService.ActivateUser(r.Context(), userID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "user activated successfully"})
}

// HandleBulkAction handles bulk actions on users for admin
func (h *AuthHandler) HandleBulkAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.BulkActionRequest
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
	response, err := h.authService.BulkAction(r.Context(), &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleGetSystemStats handles getting system statistics for admin
func (h *AuthHandler) HandleGetSystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Call service
	response, err := h.authService.GetSystemStats(r.Context())
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleGetAuditLogs handles getting audit logs for admin
func (h *AuthHandler) HandleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
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
	if limit <= 0 {
		limit = 10
	}
	sort := r.URL.Query().Get("sort")
	if sort == "" {
		sort = "created_at"
	}
	order := r.URL.Query().Get("order")
	if order == "" {
		order = "desc"
	}
	userID := r.URL.Query().Get("user_id")

	req := &dto.AuditLogsRequest{
		Page:      page,
		Limit:     limit,
		EventType: sort,
		UserID:    userID,
	}

	// Call service
	response, err := h.authService.GetAuditLogs(r.Context(), req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleGetSystemHealth handles getting system health for admin
func (h *AuthHandler) HandleGetSystemHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Call service
	response, err := h.authService.GetSystemHealth(r.Context())
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleExportUsers handles exporting users for admin
func (h *AuthHandler) HandleExportUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Parse query parameters
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	req := &dto.ExportUsersRequest{
		Format: format,
	}

	// Call service
	response, err := h.authService.ExportUsers(r.Context(), req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleInviteUser handles inviting a user for admin
func (h *AuthHandler) HandleInviteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req dto.InviteUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if err := validate.Struct(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "validation failed", err)
		return
	}

	// Get admin user ID from context (set by auth middleware)
	adminUserID := r.Context().Value("user_id").(string)

	// Call service
	response, err := h.authService.InviteUser(r.Context(), adminUserID, &req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusCreated, response)
}

// HandleListInvitations handles listing invitations for admin
func (h *AuthHandler) HandleListInvitations(w http.ResponseWriter, r *http.Request) {
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
	if limit <= 0 {
		limit = 10
	}
	req := &dto.ListInvitationsRequest{
		Page:  page,
		Limit: limit,
	}

	// Call service
	response, err := h.authService.ListInvitations(r.Context(), req)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// HandleCancelInvitation handles canceling an invitation for admin
func (h *AuthHandler) HandleCancelInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// Extract invitation ID from URL path
	invitationID := r.URL.Query().Get("id")
	if invitationID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "invitation ID is required", nil)
		return
	}

	// Call service
	if err := h.authService.CancelInvitation(r.Context(), invitationID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error(), err)
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "invitation canceled successfully"})
}
