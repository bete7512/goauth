package admin_handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/types"
)

func (h *AdminHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	// Parse and validate request
	req := &dto.SearchRequest{
		PaginationRequest: dto.PaginationRequest{
			Page:  parseIntWithDefault(r.URL.Query().Get("page"), 1),
			Limit: parseIntWithDefault(r.URL.Query().Get("limit"), 10),
			Sort:  r.URL.Query().Get("sort"),
			Order: r.URL.Query().Get("order"),
		},
		Search: r.URL.Query().Get("search"),
	}

	if err := req.Validate(); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Call service
	users, err := h.services.AdminService.ListUsers(r.Context(), req)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to list users")
		return
	}

	// Create pagination meta
	pagination := dto.PaginationMeta{
		Page:       req.Page,
		Limit:      req.Limit,
		Total:      int64(users.Pagination.Total),
		TotalPages: users.Pagination.TotalPages,
		HasNext:    users.Pagination.HasNext,
		HasPrev:    users.Pagination.HasPrev,
	}

	utils.RespondPaginated[dto.UserResponse](w, users.Users, pagination, "Users retrieved successfully")
}

// Helper functions
func parseIntWithDefault(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	if val, err := strconv.Atoi(s); err != nil {
		return val
	}
	return defaultValue
}

// HandleGetUser handles getting a specific user for admin
func (h *AdminHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	// Extract user ID from URL path
	userID := r.URL.Query().Get("id")
	if userID == "" {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrMissingFields), "User ID is required")
		return
	}

	// Call service
	response, err := h.services.AdminService.GetUser(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, http.StatusNotFound, string(types.ErrUserNotFound), err.Error())
		return
	}

	utils.RespondSuccess(w, response, "User retrieved successfully")
}

// HandleUpdateUser handles updating a user for admin
func (h *AdminHandler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	// Extract user ID from URL path
	userID := r.URL.Query().Get("id")
	if userID == "" {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrMissingFields), "User ID is required")
		return
	}

	var req dto.AdminUpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), "Validation failed")
		return
	}

	// Call service
	response, err := h.services.AdminService.UpdateUser(r.Context(), userID, &req)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to update user")
		return
	}

	utils.RespondSuccess(w, response, "User updated successfully")
}

// HandleDeleteUser handles deleting a user for admin
func (h *AdminHandler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	// Extract user ID from URL path
	userID := r.URL.Query().Get("id")
	if userID == "" {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrMissingFields), "User ID is required")
		return
	}

	// Call service
	if err := h.services.AdminService.DeleteUser(r.Context(), userID); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to delete user")
		return
	}

	utils.RespondSuccess[any](w, nil, "User deleted successfully")
}

// HandleActivateUser handles activating a user for admin
func (h *AdminHandler) HandleActivateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	// Extract user ID from URL path
	userID := r.URL.Query().Get("id")
	if userID == "" {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrMissingFields), "User ID is required")
		return
	}

	// Call service
	if err := h.services.AdminService.ActivateUser(r.Context(), userID); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to activate user")
		return
	}

	utils.RespondSuccess[any](w, nil, "User activated successfully")
}

// HandleBulkAction handles bulk actions on users for admin
func (h *AdminHandler) HandleBulkAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	var req dto.BulkActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), "Validation failed")
		return
	}

	// Call service
	response, err := h.services.AdminService.BulkAction(r.Context(), &req)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to perform bulk action")
		return
	}

	utils.RespondSuccess(w, response, "Bulk action performed successfully")
}

// HandleGetSystemStats handles getting system statistics for admin
func (h *AdminHandler) HandleGetSystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	// Call service
	response, err := h.services.AdminService.GetSystemStats(r.Context())
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to get system stats")
		return
	}

	utils.RespondSuccess(w, response, "System stats retrieved successfully")
}

// HandleGetAuditLogs handles getting audit logs for admin
func (h *AdminHandler) HandleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
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
	response, err := h.services.AdminService.GetAuditLogs(r.Context(), req)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to get audit logs")
		return
	}

	utils.RespondSuccess(w, response, "Audit logs retrieved successfully")
}

// HandleGetSystemHealth handles getting system health for admin
func (h *AdminHandler) HandleGetSystemHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	// Call service
	response, err := h.services.AdminService.GetSystemHealth(r.Context())
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to get system health")
		return
	}

	utils.RespondSuccess(w, response, "System health retrieved successfully")
}

// HandleExportUsers handles exporting users for admin
func (h *AdminHandler) HandleExportUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
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
	response, err := h.services.AdminService.ExportUsers(r.Context(), req)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to export users")
		return
	}

	utils.RespondSuccess(w, response, "Users exported successfully")
}

// HandleInviteUser handles inviting a user for admin
func (h *AdminHandler) HandleInviteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	var req dto.InviteUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), "Invalid request body")
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), "Validation failed")
		return
	}

	// Get admin user ID from context (set by auth middleware)
	adminUserID := r.Context().Value("user_id").(string)

	// Call service
	response, err := h.services.AdminService.InviteUser(r.Context(), adminUserID, &req)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to invite user")
		return
	}

	utils.RespondSuccess(w, response, "User invited successfully")
}

// HandleListInvitations handles listing invitations for admin
func (h *AdminHandler) HandleListInvitations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
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
	response, err := h.services.AdminService.ListInvitations(r.Context(), req)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to list invitations")
		return
	}

	utils.RespondSuccess(w, response, "Invitations listed successfully")
}

// HandleCancelInvitation handles canceling an invitation for admin
func (h *AdminHandler) HandleCancelInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "Method not allowed")
		return
	}

	// Extract invitation ID from URL path
	invitationID := r.URL.Query().Get("id")
	if invitationID == "" {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrMissingFields), "Invitation ID is required")
		return
	}

	// Call service
	if err := h.services.AdminService.CancelInvitation(r.Context(), invitationID); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "Failed to cancel invitation")
		return
	}

	utils.RespondSuccess[any](w, nil, "Invitation canceled successfully")
}
