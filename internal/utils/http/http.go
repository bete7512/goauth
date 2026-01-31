package http_utils

import (
	"encoding/json"
	"net/http"

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

// Error response
func RespondError(w http.ResponseWriter, statusCode int, code, message string) {
	response := types.APIResponse[interface{}]{
		Error: &types.GoAuthError{
			StatusCode: statusCode,
			Code:       types.ErrorCode(code),
			Message:    message,
		},
	}
	writeJSON(w, statusCode, response)
}

// Paginated response
func RespondPaginated[T any](w http.ResponseWriter, data []T, pagination types.PaginationMeta, message *string) {
	response := types.APIResponse[types.PaginatedResponse[T]]{
		Data: types.PaginatedResponse[T]{
			Data:       data,
			Pagination: pagination,
		},
		Message: message,
	}
	writeJSON(w, http.StatusOK, response)
}

// Write JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
