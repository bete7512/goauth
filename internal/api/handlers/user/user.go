package user_handler

import (
	"encoding/json"
	"net/http"

	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/types"
)

// HandleSendEmailVerification handles sending email verification
func (h *UserHandler) HandleSendEmailVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}
	var req dto.SendEmailVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Call service
	if err := h.services.UserService.SendEmailVerification(r.Context(), req.Email); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), err.Error())
		return
	}

	utils.RespondSuccess[any](w, nil, "email verification sent")
}

// HandleSendPhoneVerification handles sending phone verification
func (h *UserHandler) HandleSendPhoneVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}
	var req dto.SendPhoneVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}
	// Call service
	if err := h.services.UserService.SendPhoneVerification(r.Context(), req.PhoneNumber); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), "failed to send phone verification")
		return
	}

	utils.RespondSuccess[any](w, nil, "phone verification code sent")
}

// HandleVerifyEmail handles email verification
func (h *UserHandler) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {

	var req dto.EmailVerificationRequest
	if r.Method == http.MethodGet {
		// get token and email
		token := r.URL.Query().Get("token")
		email := r.URL.Query().Get("email")
		if token == "" || email == "" {
			utils.RespondError(w, http.StatusBadRequest, string(types.ErrMissingFields), "token and email are required")
			return
		}
		req = dto.EmailVerificationRequest{
			Token: token,
			Email: email,
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
			return
		}
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Call service
	if err := h.services.UserService.VerifyEmail(r.Context(), &req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	utils.RespondSuccess[any](w, nil, "email verified successfully")
}

// HandleVerifyPhone handles phone verification
func (h *UserHandler) HandleVerifyPhone(w http.ResponseWriter, r *http.Request) {
	var req dto.PhoneVerificationRequest
	if r.Method == http.MethodGet {
		// get token and phone number
		code := r.URL.Query().Get("code")
		phoneNumber := r.URL.Query().Get("phone_number")
		if code == "" || phoneNumber == "" {
			utils.RespondError(w, http.StatusBadRequest, string(types.ErrMissingFields), "code and phone number are required")
			return
		}
		req = dto.PhoneVerificationRequest{
			Code:        code,
			PhoneNumber: phoneNumber,
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
			return
		}
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Call service
	if err := h.services.UserService.VerifyPhone(r.Context(), &req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	utils.RespondSuccess[any](w, nil, "phone verified successfully")
}

// HandleSendActionConfirmation handles sending action confirmation
func (h *UserHandler) HandleSendActionConfirmation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.ActionConfirmationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.services.UserService.SendActionConfirmation(r.Context(), userID, &req); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess[any](w, nil, "action confirmation sent")
}

// HandleVerifyActionConfirmation handles action confirmation verification
func (h *UserHandler) HandleVerifyActionConfirmation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.ActionConfirmationVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.services.UserService.VerifyActionConfirmation(r.Context(), userID, &req); err != nil {
		utils.RespondError(w, err.StatusCode, string(err.Code), err.Message)
		return
	}

	utils.RespondSuccess[any](w, nil, "action confirmed successfully")
}

// HandleUpdateProfile handles user profile updates
func (h *UserHandler) HandleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	response, err := h.services.UserService.UpdateProfile(r.Context(), userID, &req)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), err.Error())
		return
	}

	utils.RespondSuccess(w, response, "profile updated successfully")
}

// HandleGetMe handles getting current user information
func (h *UserHandler) HandleGetMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	response, err := h.services.UserService.GetUserByID(r.Context(), userID)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, string(types.ErrInternalError), err.Error())
		return
	}

	utils.RespondSuccess(w, response, "user retrieved successfully")
}

// HandleDeactivateUser handles user account deactivation
func (h *UserHandler) HandleDeactivateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondError(w, http.StatusMethodNotAllowed, string(types.ErrMethodNotAllowed), "method not allowed")
		return
	}

	var req dto.DeactivateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrValidation), err.Error())
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := r.Context().Value("user_id").(string)

	// Call service
	if err := h.services.UserService.DeactivateUser(r.Context(), userID, &req); err != nil {
		utils.RespondError(w, http.StatusBadRequest, string(types.ErrInvalidRequestBody), err.Error())
		return
	}

	// clearAuthCookies(w)

	utils.RespondSuccess[any](w, nil, "account deactivated successfully")
}
