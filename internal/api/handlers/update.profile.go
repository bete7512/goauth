package handlers

import (
	"encoding/json"
	"net/http"
)

// ProfileUpdateRequest represents the data structure for profile updates
type ProfileUpdateRequest struct {
	Name   string `json:"name,omitempty"`
	Bio    string `json:"bio,omitempty"`
	Avatar string `json:"avatar,omitempty"`
	// Add other profile-specific fields as needed
}

// HandleUpdateProfile handles user profile updates specifically
func (h *AuthRoutes) HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var profileData ProfileUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&profileData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user ID from context (assuming authentication middleware sets this)
	userID := r.Context().Value("user_id")
	if userID == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Update profile logic here
	// This should be implemented according to your specific requirements
	// Example:
	// err := h.Auth.DB.UpdateUserProfile(userID.(string), profileData)
	// if err != nil {
	//     http.Error(w, "Failed to update profile", http.StatusInternalServerError)
	//     return
	// }

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Profile updated successfully",
	})
}
