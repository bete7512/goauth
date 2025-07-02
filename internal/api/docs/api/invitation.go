package doc_api

// @Summary Invite a new user
// @Description Admin endpoint to invite a new user via email
// @Tags Admin
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param invitation body InviteUserRequest true "Invitation details"
// @Success 200 {object} InviteUserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/invitations [post]
func InviteUser() {}

// @Summary List pending invitations
// @Description Admin endpoint to list all pending invitations
// @Tags Admin
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} ListInvitationsResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/invitations [get]
func ListInvitations() {}

// @Summary Cancel invitation
// @Description Admin endpoint to cancel a pending invitation
// @Tags Admin
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param id path string true "Invitation ID"
// @Success 200 {object} CancelInvitationResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/invitations/{id} [delete]
func CancelInvitation() {}

// @Summary Register with invitation
// @Description Public endpoint to complete registration with invitation token
// @Tags Auth
// @Accept json
// @Produce json
// @Param registration body RegisterWithInvitationRequest true "Registration details"
// @Success 201 {object} RegisterWithInvitationResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /register/invitation [post]
func RegisterWithInvitation() {}

// InviteUserRequest represents the request body for inviting a user
type InviteUserRequest struct {
	Email     string `json:"email" validate:"required,email" example:"john.doe@example.com"`
	FirstName string `json:"first_name" validate:"required" example:"John"`
	LastName  string `json:"last_name" validate:"required" example:"Doe"`
	IsAdmin   bool   `json:"is_admin" example:"false"`
	Message   string `json:"message" example:"Welcome to our platform!"`
}

// InviteUserResponse represents the response for inviting a user
type InviteUserResponse struct {
	Message string `json:"message" example:"invitation sent successfully"`
	Email   string `json:"email" example:"john.doe@example.com"`
	Expires string `json:"expires" example:"24 hours"`
}

// ListInvitationsResponse represents the response for listing invitations
type ListInvitationsResponse struct {
	Invitations []InvitationData `json:"invitations"`
	Pagination  Pagination       `json:"pagination"`
}

// InvitationData represents an invitation
type InvitationData struct {
	ID        string `json:"id" example:"uuid"`
	Email     string `json:"email" example:"john.doe@example.com"`
	FirstName string `json:"first_name" example:"John"`
	LastName  string `json:"last_name" example:"Doe"`
	IsAdmin   bool   `json:"is_admin" example:"false"`
	InvitedBy string `json:"invited_by" example:"admin@example.com"`
	Message   string `json:"message" example:"Welcome to our platform!"`
	CreatedAt string `json:"created_at" example:"2024-01-01T00:00:00Z"`
	ExpiresAt string `json:"expires_at" example:"2024-01-02T00:00:00Z"`
}

// CancelInvitationResponse represents the response for canceling an invitation
type CancelInvitationResponse struct {
	Message string `json:"message" example:"invitation canceled successfully"`
}

// RegisterWithInvitationRequest represents the request body for registering with invitation
type RegisterWithInvitationRequest struct {
	Email           string `json:"email" validate:"required,email" example:"john.doe@example.com"`
	Password        string `json:"password" validate:"required,min=8" example:"securepassword123"`
	FirstName       string `json:"first_name" validate:"required" example:"John"`
	LastName        string `json:"last_name" validate:"required" example:"Doe"`
	InvitationToken string `json:"invitation_token" validate:"required" example:"abc123..."`
}

// RegisterWithInvitationResponse represents the response for registering with invitation
type RegisterWithInvitationResponse struct {
	Message string   `json:"message" example:"registration successful"`
	User    UserData `json:"user"`
}

// Pagination represents pagination information
type Pagination struct {
	Page       int `json:"page" example:"1"`
	Limit      int `json:"limit" example:"20"`
	Total      int `json:"total" example:"100"`
	TotalPages int `json:"total_pages" example:"5"`
}

// UserData represents user information in responses
type UserData struct {
	ID        string `json:"id" example:"uuid"`
	Email     string `json:"email" example:"john.doe@example.com"`
	FirstName string `json:"first_name" example:"John"`
	LastName  string `json:"last_name" example:"Doe"`
	Active    *bool  `json:"active" example:"true"`
	IsAdmin   *bool  `json:"is_admin" example:"false"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error" example:"error message"`
	Message string `json:"message" example:"detailed error message"`
}
