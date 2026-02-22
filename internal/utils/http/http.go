package http_utils

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Success response
func RespondSuccess[T any](w http.ResponseWriter, data T, message *string) {
	response := types.APIResponse[T]{
		Data:    data,
		Message: message,
	}
	writeJSON(w, http.StatusOK, response)
}

// RespondCreated writes a 201 Created response (for resource creation endpoints).
func RespondCreated[T any](w http.ResponseWriter, data T, message *string) {
	response := types.APIResponse[T]{
		Data:    data,
		Message: message,
	}
	writeJSON(w, http.StatusCreated, response)
}

// 

// Error response
func RespondError(w http.ResponseWriter, statusCode int, code, message string) {
	response := types.APIResponse[interface{}]{
		Data: &types.GoAuthError{
			StatusCode: statusCode,
			Code:       types.ErrorCode(code),
			Message:    message,
		},
	}
	writeJSON(w, statusCode, response)
}

// RespondList writes a standardized list response.
func RespondList[T any](w http.ResponseWriter, items []T, total int64, sortField, sortDir string) {
	if items == nil {
		items = []T{}
	}
	response := types.APIResponse[types.ListResponse[T]]{
		Data: types.ListResponse[T]{
			List:      items,
			SortField: sortField,
			SortDir:   sortDir,
			Total:     total,
		},
	}
	writeJSON(w, http.StatusOK, response)
}

// ParseListingOpts extracts the common pagination/sorting query parameters.
// Validation is deferred to the per-entity Normalize method.
func ParseListingOpts(r *http.Request) models.ListingOpts {
	opts := models.DefaultListingOpts()

	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			opts.Limit = parsed
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			opts.Offset = parsed
		}
	}
	if v := r.URL.Query().Get("sort_field"); v != "" {
		opts.SortField = v
	}
	if v := r.URL.Query().Get("sort_dir"); v != "" {
		opts.SortDir = v
	}

	return opts
}

// Write JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
