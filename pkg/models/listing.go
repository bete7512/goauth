package models

import "strings"

// ListingOpts holds shared pagination and sorting parameters.
type ListingOpts struct {
	Offset    int
	Limit     int
	SortField string
	SortDir   string // "asc" or "desc"
}

// DefaultListingOpts returns listing options with safe defaults.
func DefaultListingOpts() ListingOpts {
	return ListingOpts{
		Offset:    0,
		Limit:     20,
		SortField: "created_at",
		SortDir:   "desc",
	}
}

// Normalize clamps values to safe ranges and validates sort field against an allowlist.
func (o *ListingOpts) Normalize(maxLimit int, allowedSortFields map[string]bool) {
	if o.Limit <= 0 {
		o.Limit = 20
	}
	if maxLimit > 0 && o.Limit > maxLimit {
		o.Limit = maxLimit
	}
	if o.Offset < 0 {
		o.Offset = 0
	}
	if o.SortDir != "asc" && o.SortDir != "desc" {
		o.SortDir = "desc"
	}
	if o.SortField == "" || !allowedSortFields[o.SortField] {
		o.SortField = "created_at"
	}
}

// --- Per-entity opts ---

// UserListOpts extends ListingOpts with user-specific filters.
type UserListOpts struct {
	ListingOpts
	Query string // search name/email/username
}

// Normalize validates and clamps all fields.
func (o *UserListOpts) Normalize(maxLimit int) {
	o.ListingOpts.Normalize(maxLimit, userSortFields)
	o.Query = strings.TrimSpace(o.Query)
}

// SessionListOpts extends ListingOpts with session-specific filters.
type SessionListOpts struct {
	ListingOpts
}

// Normalize validates and clamps all fields.
func (o *SessionListOpts) Normalize(maxLimit int) {
	o.ListingOpts.Normalize(maxLimit, sessionSortFields)
}

// AuditLogListOpts extends ListingOpts with audit-log-specific filters.
type AuditLogListOpts struct {
	ListingOpts
}

// Normalize validates and clamps all fields.
func (o *AuditLogListOpts) Normalize(maxLimit int) {
	o.ListingOpts.Normalize(maxLimit, auditLogSortFields)
}

// --- Sort field allowlists (unexported — accessed via entity Normalize) ---
var userSortFields = map[string]bool{
	"created_at": true,
	"email":      true,
	"username":   true,
	"name":       true,
}

var sessionSortFields = map[string]bool{
	"created_at": true,
	"expires_at": true,
	"ip_address": true,
}

var auditLogSortFields = map[string]bool{
	"created_at": true,
	"action":     true,
	"severity":   true,
	"actor_id":   true,
}
