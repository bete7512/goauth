package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/schemas"
	"github.com/bete7512/goauth/internal/utils"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// RegistrationResult holds the result of user registration
type RegistrationResult struct {
	User                 *types.User
	RequiresVerification bool
	VerificationMessage  string
	AccessToken          string
	RefreshToken         string
}

// HandleRegister handles user registration with improved structure and error handling
func (h *AuthRoutes) HandleRegister(w http.ResponseWriter, r *http.Request) {
	// 1. Method validation
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	// 2. Parse and validate request
	req, rawData, err := h.parseRegistrationRequest(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// 3.0 Validate request data
	if err := h.validateRegistrationRequest(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	// 3.1 Validate recaptcha if enabled
	if h.Auth.Config.Security.Recaptcha.Enabled && h.Auth.RecaptchaManager != nil && h.Auth.Config.Security.Recaptcha.Routes[config.RouteRegister] {
		if req.RecaptchaToken == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "recaptcha token is required", nil)
			return
		}
		// TODO: add
		ip := utils.GetIpFromRequest(r)
		ok, err := h.Auth.RecaptchaManager.Verify(r.Context(), req.RecaptchaToken, ip)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "recaptcha verification failed: "+err.Error(), nil)
			return
		}
		if !ok {
			utils.RespondWithError(w, http.StatusBadRequest, "recaptcha verification failed", nil)
			return
		}
	}

	// 4. Check for existing user and create new user
	result, err := h.createUserAccount(r.Context(), req)
	if err != nil {
		if errors.Is(err, ErrEmailAlreadyExists) {
			utils.RespondWithError(w, http.StatusConflict, "email already exists", nil)
			return
		}
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to create user account", nil)
		return
	}

	// 5. Handle verification flows if needed
	if result.RequiresVerification {
		if err := h.handleVerificationFlow(r.Context(), result.User); err != nil {
			h.Auth.Logger.Errorf("Failed to send verification: %v", err)
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to send verification", nil)
			return
		}
	}

	// 7. Prepare and send response
	response := h.buildRegistrationResponse(result)
	// 6. Set authentication cookies if tokens were generated
	if result.AccessToken != "" && result.RefreshToken != "" && h.Auth.Config.AuthConfig.Methods.Type == config.AuthenticationTypeCookie {
		h.setAccessTokenCookie(w, result.AccessToken)
		h.setRefreshTokenCookie(w, result.RefreshToken)
	} else {
		response["access_token"] = result.AccessToken
		response["refresh_token"] = result.RefreshToken
	}

	// TODO: add logs to audit log account created and other information
	// 8. Handle hooks if configured
	if h.Auth.HookManager.GetAfterHook(config.RouteRegister) != nil {
		ctx := context.WithValue(r.Context(), config.RequestDataKey, rawData)
		ctx = context.WithValue(ctx, config.ResponseDataKey, response)
		r = r.WithContext(ctx)
		h.Auth.HookManager.ExecuteAfterHooks(config.RouteRegister, w, r)
		return
	}

	// Send standard response
	statusCode := http.StatusCreated
	if result.RequiresVerification {
		statusCode = http.StatusAccepted
	}

	if err := utils.RespondWithJSON(w, statusCode, response); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to send response", nil)
		return
	}

	// Send welcome email asynchronously if configured and user is active
	if !result.RequiresVerification && h.Auth.Config.AuthConfig.Methods.EmailVerification.SendWelcomeEmail {
		h.Auth.WorkerPool.Submit(func() {
			if err := h.Auth.Config.Email.Sender.CustomSender.SendWelcomeEmail(context.Background(), *result.User); err != nil {
				h.Auth.Logger.Errorf("Failed to send welcome email to user %d: %v", result.User.ID, err)
			}
		})
	}
}

// parseRegistrationRequest handles request parsing with hook support
func (h *AuthRoutes) parseRegistrationRequest(r *http.Request) (*schemas.RegisterRequest, map[string]interface{}, error) {
	var req schemas.RegisterRequest
	var rawData map[string]interface{}

	// Handle hooks that need raw data
	if h == nil {
		log.Println("Auth is nil>>>>>>>>>>>>>>>>>>>>>>>>>>>>>l")
		return nil, nil, fmt.Errorf("hook manager is not initialized")
	}
	if h.Auth.HookManager.GetAfterHook(config.RouteRegister) != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read request body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if err := json.Unmarshal(bodyBytes, &rawData); err != nil {
			return nil, nil, fmt.Errorf("invalid request body json: %w", err)
		}

		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			return nil, nil, fmt.Errorf("invalid request format: %w", err)
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, nil, fmt.Errorf("invalid request body: %w", err)
		}
	}

	return &req, rawData, nil
}

// validateRegistrationRequest validates all registration request fields
func (h *AuthRoutes) validateRegistrationRequest(req *schemas.RegisterRequest) error {

	// Normalize email
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Validate password against policy
	if err := h.validatePasswordPolicy(req.Password, h.Auth.Config.AuthConfig.PasswordPolicy); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	// Validate email format
	if err := h.ValidateEmail(req.Email); err != nil {
		return fmt.Errorf("email validation failed: %w", err)
	}

	// Validate email domain if configured
	if err := h.validateEmailDomain(req.Email); err != nil {
		return fmt.Errorf("email domain validation failed: %w", err)
	}

	// Validate phone number if provided
	if req.PhoneNumber != nil && *req.PhoneNumber != "" {
		if err := h.ValidatePhoneNumber(req.PhoneNumber); err != nil {
			return fmt.Errorf("phone number validation failed: %w", err)
		}
	}

	// Validate required phone number for phone verification
	if h.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup && req.PhoneNumber == nil {
		return errors.New("phone number is required when phone verification is enabled")
	}

	return nil
}

// Custom error types
var (
	ErrEmailAlreadyExists = errors.New("email already exists")
)

// createUserAccount creates a new user account with proper transaction handling
func (h *AuthRoutes) createUserAccount(ctx context.Context, req *schemas.RegisterRequest) (*RegistrationResult, error) {
	// Check if email already exists
	existingUser, err := h.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}
	if existingUser != nil {
		return nil, ErrEmailAlreadyExists
	}

	// Hash password
	hashedPassword, err := h.Auth.TokenManager.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Determine if verification is required
	requiresEmailVerification := h.Auth.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup
	requiresPhoneVerification := h.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup
	requiresVerification := requiresEmailVerification || requiresPhoneVerification

	// Create user object
	active := !requiresVerification
	twoFactorEnabled := false
	emailVerified := !requiresEmailVerification
	phoneVerified := !requiresPhoneVerification

	user := types.User{
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		Email:            req.Email,
		Password:         hashedPassword,
		Active:           &active,
		TwoFactorEnabled: &twoFactorEnabled,
		SignedUpVia:      "email",
		PhoneNumber:      req.PhoneNumber,
		EmailVerified:    &emailVerified,
		PhoneVerified:    &phoneVerified,
	}

	// Create user in database
	if err := h.Auth.Repository.GetUserRepository().CreateUser(ctx, &user); err != nil {
		return nil, fmt.Errorf("failed to create user in database: %w", err)
	}

	result := &RegistrationResult{
		User:                 &user,
		RequiresVerification: requiresVerification,
	}

	// Generate tokens if no verification is required
	if !requiresVerification {
		accessToken, refreshToken, err := h.Auth.TokenManager.GenerateTokens(&user)
		if err != nil {
			return nil, fmt.Errorf("failed to generate authentication tokens: %w", err)
		}
		// Save refresh token
		if err := h.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, refreshToken, types.RefreshToken, h.Auth.Config.AuthConfig.JWT.RefreshTokenTTL); err != nil {
			return nil, fmt.Errorf("failed to save refresh token: %w", err)
		}

		result.AccessToken = accessToken
		result.RefreshToken = refreshToken
	}

	return result, nil
}

// handleVerificationFlow handles email and/or phone verification setup
func (h *AuthRoutes) handleVerificationFlow(ctx context.Context, user *types.User) error {

	// Handle email verification
	if h.Auth.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup {
		if err := h.setupEmailVerification(ctx, user); err != nil {
			return fmt.Errorf("failed to setup email verification: %w", err)
		}
	}

	// Handle phone verification
	if h.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup {
		if err := h.setupPhoneVerification(ctx, user); err != nil {
			return fmt.Errorf("failed to setup phone verification: %w", err)
		}
	}

	return nil
}

// buildRegistrationResponse builds the appropriate response based on registration result
func (h *AuthRoutes) buildRegistrationResponse(result *RegistrationResult) map[string]interface{} {
	userResponse := map[string]interface{}{
		"id":           result.User.ID,
		"first_name":   result.User.FirstName,
		"last_name":    result.User.LastName,
		"email":        result.User.Email,
		"phone_number": result.User.PhoneNumber,
		"active":       result.User.Active,
		"signin_via":   result.User.SignedUpVia,
		"created_at":   result.User.CreatedAt,
	}

	if result.RequiresVerification {
		// Build verification message
		var message string
		requiresEmail := h.Auth.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup
		requiresPhone := h.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup

		if requiresEmail && requiresPhone {
			message = "verification links and codes sent to email and phone number"
		} else if requiresEmail {
			message = "verification link sent to email"
		} else {
			message = "verification otp sent to phone number"
		}

		userResponse["email_verified"] = result.User.EmailVerified
		userResponse["phone_verified"] = result.User.PhoneVerified
		userResponse["message"] = message
	}

	return userResponse
}
