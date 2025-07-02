package dto

import "time"

// ListUsersRequest represents user listing request
type ListUsersRequest struct {
	Page     int    `json:"page" validate:"min=1"`
	Limit    int    `json:"limit" validate:"min=1,max=100"`
	Search   string `json:"search,omitempty"`
	SortBy   string `json:"sort_by,omitempty"`
	SortDir  string `json:"sort_dir,omitempty"`
	IsActive *bool  `json:"is_active,omitempty"`
	IsAdmin  *bool  `json:"is_admin,omitempty"`
}

// ListUsersResponse represents user listing response
type ListUsersResponse struct {
	Users      []AdminUserData `json:"users"`
	Pagination Pagination      `json:"pagination"`
}

// AdminUserData represents admin user information
type AdminUserData struct {
	ID               string     `json:"id"`
	Email            string     `json:"email"`
	FirstName        string     `json:"first_name"`
	LastName         string     `json:"last_name"`
	PhoneNumber      *string    `json:"phone_number,omitempty"`
	EmailVerified    *bool      `json:"email_verified"`
	PhoneVerified    *bool      `json:"phone_verified"`
	TwoFactorEnabled *bool      `json:"two_factor_enabled"`
	Active           *bool      `json:"active"`
	IsAdmin          *bool      `json:"is_admin"`
	Avatar           *string    `json:"avatar,omitempty"`
	ProviderID       *string    `json:"provider_id,omitempty"`
	SignedUpVia      string     `json:"signed_up_via"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	IsDeleted        *bool      `json:"is_deleted"`
}

// AdminUpdateUserRequest represents admin user update request
type AdminUpdateUserRequest struct {
	FirstName        *string `json:"first_name,omitempty"`
	LastName         *string `json:"last_name,omitempty"`
	Email            *string `json:"email,omitempty"`
	PhoneNumber      *string `json:"phone_number,omitempty"`
	EmailVerified    *bool   `json:"email_verified,omitempty"`
	PhoneVerified    *bool   `json:"phone_verified,omitempty"`
	TwoFactorEnabled *bool   `json:"two_factor_enabled,omitempty"`
	Active           *bool   `json:"active,omitempty"`
	IsAdmin          *bool   `json:"is_admin,omitempty"`
	Avatar           *string `json:"avatar,omitempty"`
}

// AdminUserResponse represents admin user response
type AdminUserResponse struct {
	Message string        `json:"message"`
	User    AdminUserData `json:"user"`
}

// BulkActionRequest represents bulk action request
type BulkActionRequest struct {
	Action  string   `json:"action" validate:"required"`
	UserIDs []string `json:"user_ids" validate:"required,min=1"`
}

// BulkActionResponse represents bulk action response
type BulkActionResponse struct {
	Message      string   `json:"message"`
	SuccessCount int      `json:"success_count"`
	FailedCount  int      `json:"failed_count"`
	FailedIDs    []string `json:"failed_ids,omitempty"`
}

// SystemStatsResponse represents system statistics response
type SystemStatsResponse struct {
	TotalUsers          int64 `json:"total_users"`
	ActiveUsers         int64 `json:"active_users"`
	InactiveUsers       int64 `json:"inactive_users"`
	AdminUsers          int64 `json:"admin_users"`
	VerifiedUsers       int64 `json:"verified_users"`
	UnverifiedUsers     int64 `json:"unverified_users"`
	TwoFactorUsers      int64 `json:"two_factor_users"`
	RecentRegistrations int64 `json:"recent_registrations"`
	RecentLogins        int64 `json:"recent_logins"`
}

// AuditLogsRequest represents audit logs request
type AuditLogsRequest struct {
	Page      int       `json:"page" validate:"min=1"`
	Limit     int       `json:"limit" validate:"min=1,max=100"`
	UserID    string    `json:"user_id,omitempty"`
	EventType string    `json:"event_type,omitempty"`
	StartDate time.Time `json:"start_date,omitempty"`
	EndDate   time.Time `json:"end_date,omitempty"`
}

// AuditLogsResponse represents audit logs response
type AuditLogsResponse struct {
	Logs       []AuditLogData `json:"logs"`
	Pagination Pagination     `json:"pagination"`
}

// AuditLogData represents audit log entry
type AuditLogData struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	EventType string                 `json:"event_type"`
	Details   map[string]interface{} `json:"details"`
	IP        string                 `json:"ip"`
	CreatedAt time.Time              `json:"created_at"`
}

// SystemHealthResponse represents system health response
type SystemHealthResponse struct {
	Status    string                   `json:"status"`
	Timestamp time.Time                `json:"timestamp"`
	Services  map[string]ServiceHealth `json:"services"`
}

// ServiceHealth represents individual service health
type ServiceHealth struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Latency int64  `json:"latency_ms,omitempty"`
}

// ExportUsersRequest represents user export request
type ExportUsersRequest struct {
	Format  string           `json:"format" validate:"required,oneof=csv json"`
	Filters ListUsersRequest `json:"filters,omitempty"`
}

// ExportUsersResponse represents user export response
type ExportUsersResponse struct {
	Message     string          `json:"message"`
	DownloadURL string          `json:"download_url,omitempty"`
	Data        []AdminUserData `json:"data,omitempty"`
}

// InviteUserRequest represents user invitation request
type InviteUserRequest struct {
	Email     string `json:"email" validate:"required,email"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
	IsAdmin   bool   `json:"is_admin"`
	Message   string `json:"message"`
}

// InviteUserResponse represents user invitation response
type InviteUserResponse struct {
	Message string `json:"message"`
	Email   string `json:"email"`
	Expires string `json:"expires"`
}

// ListInvitationsRequest represents invitation listing request
type ListInvitationsRequest struct {
	Page  int `json:"page" validate:"min=1"`
	Limit int `json:"limit" validate:"min=1,max=100"`
}

// ListInvitationsResponse represents invitation listing response
type ListInvitationsResponse struct {
	Invitations []InvitationData `json:"invitations"`
	Pagination  Pagination       `json:"pagination"`
}

// InvitationData represents invitation information
type InvitationData struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	IsAdmin   bool      `json:"is_admin"`
	InvitedBy string    `json:"invited_by"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Pagination represents pagination information
type Pagination struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}
