package utils

import (
	"encoding/json"
	"log"
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
	// TODO:only show error in dev mode
	// if err != nil && !isProd() {
	// 	response.Error = err.Error()
	// }
	if err != nil {
		// TODO: trace back and log error here
		// I want  file path and line where error occured
		log.Println()
		log.Printf("error: %v)", err)
		response.Error = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
