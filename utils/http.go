package utils

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/models"
)

func RespondWithJSON(w http.ResponseWriter, status int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

func RespondWithError(w http.ResponseWriter, status int, message string, err error) {
	response := models.ErrorResponse{
		Status:  status,
		Message: message,
	}
	if err != nil {
		response.Error = err.Error()
	}

	// TODO:only show error in dev mode
	// if err != nil && !isProd() {
	// 	response.Error = err.Error()
	// }

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
