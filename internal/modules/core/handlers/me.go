package handlers

import (
	"net/http"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
)

func (h *CoreHandler) Me(w http.ResponseWriter, r *http.Request) {
	// ctx := r.Context()

	// TODO: Get user ID from context (set by auth middleware)
	// userID := ctx.Value("user_id").(string)

	// TODO: Implement me logic
	// 1. Get user from database
	// 2. Return user data

	http_utils.RespondSuccess(w, dto.UserDTO{
		ID:            "user-123",
		Email:         "user@example.com",
		Username:      "username",
		Name:          "User Name",
		Avatar:        "https://avatar.com/user.jpg",
		Phone:         "+1234567890",
		Active:        true,
		EmailVerified: true,
		PhoneVerified: false,
		CreatedAt:     "2024-01-01T00:00:00Z",
		UpdatedAt:     "2024-01-01T00:00:00Z",
	}, nil)
}
