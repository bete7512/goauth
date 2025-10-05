package http_utils

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/types"
)

// Success response
func RespondSuccess[T any](w http.ResponseWriter, data T, message *string) {
	response := types.APIResponse[T]{
		Success:   true,
		Data:      data,
		Message:   message,
		Timestamp: time.Now(),
	}
	writeJSON(w, http.StatusOK, response)
}

// Error response
func RespondError(w http.ResponseWriter, statusCode int, code, message string) {
	response := types.APIResponse[interface{}]{
		Success: false,
		Error: &types.GoAuthError{
			StatusCode: statusCode,
			Code:       types.ErrorCode(code),
			Message:    message,
		},
		Timestamp: time.Now(),
	}
	writeJSON(w, statusCode, response)
}

// Paginated response
func RespondPaginated[T any](w http.ResponseWriter, data []T, pagination types.PaginationMeta, message *string) {
	response := types.APIResponse[types.PaginatedResponse[T]]{
		Success: true,
		Data: types.PaginatedResponse[T]{
			Data:       data,
			Pagination: pagination,
		},
		Message:   message,
		Timestamp: time.Now(),
	}
	writeJSON(w, http.StatusOK, response)
}

// Write JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
