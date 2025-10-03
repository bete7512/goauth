package handlers

import (
	"net/http"
)

func (h *CoreHandler) Signup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// TODO: Parse request body
	// var signupData SignupRequest

	// Emit BEFORE signup event for validation
	if err := h.deps.Events.EmitSync(ctx, "before:signup", map[string]interface{}{
		"email": "user@example.com", // TODO: get from request
	}); err != nil {
		http.Error(w, "Signup validation failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: Create user in database
	user := map[string]interface{}{
		"id":    "user-123",
		"email": "user@example.com",
	}

	// Emit AFTER signup event (async operations like sending email)
	h.deps.Events.Emit(ctx, "after:signup", user)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "User created successfully"}`))
}
