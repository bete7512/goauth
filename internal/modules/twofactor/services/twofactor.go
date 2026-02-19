package services

//go:generate mockgen -destination=../../../mocks/mock_twofactor_service.go -package=mocks github.com/bete7512/goauth/internal/modules/twofactor/services TwoFactorService

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// TwoFactorService interface - exported for testing
type TwoFactorService interface {
	// Setup & Configuration
	GenerateSecret(ctx context.Context, userEmail string) (secret string, qrURL string, authErr *types.GoAuthError)
	SaveTwoFactorConfig(ctx context.Context, tfConfig *models.TwoFactor) *types.GoAuthError
	GetTwoFactorConfig(ctx context.Context, userID string) (*models.TwoFactor, *types.GoAuthError)

	// TOTP Verification
	VerifyCode(ctx context.Context, userID, code string) *types.GoAuthError
	VerifyCodeManual(ctx context.Context, secret, code string) *types.GoAuthError
	EnableTwoFactor(ctx context.Context, userID string) *types.GoAuthError
	DisableTwoFactor(ctx context.Context, userID string) *types.GoAuthError

	// Backup Codes
	GenerateBackupCodes(ctx context.Context, userID string) (plainCodes []string, authErr *types.GoAuthError)
	SaveBackupCodes(ctx context.Context, userID string, plainCodes []string) *types.GoAuthError
	UseBackupCode(ctx context.Context, userID, plainCode string) *types.GoAuthError

	// Combined verification (TOTP or backup code)
	VerifyCodeOrBackup(ctx context.Context, userID, code string) *types.GoAuthError

	// User operations (avoids handler accessing repositories directly)
	GetUser(ctx context.Context, userID string) (*models.User, *types.GoAuthError)

	// Token issuance after 2FA verification (avoids handler accessing repositories)
	IssueAuthTokenAfter2FA(ctx context.Context, user *models.User, metadata *types.RequestMetadata) (map[string]any, *types.GoAuthError)
}

// twoFactorService - unexported implementation
type twoFactorService struct {
	deps             config.ModuleDependencies
	issuer           string
	backupCodesCount int
	codeLength       int
}

// NewTwoFactorService creates a new two-factor service
func NewTwoFactorService(deps config.ModuleDependencies, issuer string, backupCodesCount, codeLength int) *twoFactorService {
	return &twoFactorService{
		deps:             deps,
		issuer:           issuer,
		backupCodesCount: backupCodesCount,
		codeLength:       codeLength,
	}
}

// GenerateSecret generates a new TOTP secret and provisioning URL
func (s *twoFactorService) GenerateSecret(ctx context.Context, userEmail string) (string, string, *types.GoAuthError) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: userEmail,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		s.deps.Logger.Error("Failed to generate TOTP secret", "error", err)
		return "", "", types.NewInternalError("Failed to generate 2FA secret")
	}

	return key.Secret(), key.URL(), nil
}

// SaveTwoFactorConfig saves or updates 2FA configuration
func (s *twoFactorService) SaveTwoFactorConfig(ctx context.Context, tfConfig *models.TwoFactor) *types.GoAuthError {
	tfRepo := s.deps.Storage.TwoFactorAuth().TwoFactor()

	// Check if config already exists
	existing, err := tfRepo.GetByUserID(ctx, tfConfig.UserID)
	if err != nil {
		s.deps.Logger.Error("Failed to check existing 2FA config", "error", err)
		return types.NewInternalError("Failed to save 2FA configuration")
	}

	if existing != nil {
		// Update existing
		tfConfig.ID = existing.ID
		tfConfig.CreatedAt = existing.CreatedAt
		if err := tfRepo.Update(ctx, tfConfig); err != nil {
			s.deps.Logger.Error("Failed to update 2FA config", "error", err)
			return types.NewInternalError("Failed to update 2FA configuration")
		}
	} else {
		// Create new
		tfConfig.ID = uuid.New().String()
		if err := tfRepo.Create(ctx, tfConfig); err != nil {
			s.deps.Logger.Error("Failed to create 2FA config", "error", err)
			return types.NewInternalError("Failed to save 2FA configuration")
		}
	}

	return nil
}

// GetTwoFactorConfig retrieves 2FA configuration for a user
func (s *twoFactorService) GetTwoFactorConfig(ctx context.Context, userID string) (*models.TwoFactor, *types.GoAuthError) {
	tfRepo := s.deps.Storage.TwoFactorAuth().TwoFactor()

	tfConfig, err := tfRepo.GetByUserID(ctx, userID)
	if err != nil {
		s.deps.Logger.Error("Failed to get 2FA config", "error", err)
		return nil, types.NewInternalError("Failed to retrieve 2FA configuration")
	}

	if tfConfig == nil {
		return nil, types.NewTwoFactorNotFoundError()
	}

	return tfConfig, nil
}

// VerifyCode verifies a TOTP code
func (s *twoFactorService) VerifyCode(ctx context.Context, userID, code string) *types.GoAuthError {
	// Get 2FA config
	tfConfig, authErr := s.GetTwoFactorConfig(ctx, userID)
	if authErr != nil {
		return authErr
	}

	if !tfConfig.Enabled {
		return types.NewTwoFactorNotEnabledError()
	}

	// Verify TOTP code with time window tolerance (±1 period = 60s total window)
	valid, err := totp.ValidateCustom(code, tfConfig.Secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // Allow ±1 time window (30s before and after)
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil || !valid {
		s.deps.Logger.Warn("Invalid 2FA code attempt", "user_id", userID)
		return types.NewTwoFactorInvalidError()
	}

	// TODO: Add code reuse prevention (cache used codes for 60s) in future version
	return nil
}

// EnableTwoFactor enables 2FA for a user
func (s *twoFactorService) EnableTwoFactor(ctx context.Context, userID string) *types.GoAuthError {
	tfRepo := s.deps.Storage.TwoFactorAuth().TwoFactor()

	tfConfig, err := tfRepo.GetByUserID(ctx, userID)
	if err != nil {
		s.deps.Logger.Error("Failed to get 2FA config", "error", err)
		return types.NewInternalError("Failed to enable 2FA")
	}

	if tfConfig == nil {
		return types.NewTwoFactorNotFoundError()
	}

	tfConfig.Enabled = true
	tfConfig.Verified = true

	if err := tfRepo.Update(ctx, tfConfig); err != nil {
		s.deps.Logger.Error("Failed to enable 2FA", "error", err)
		return types.NewInternalError("Failed to enable 2FA")
	}

	return nil
}

// DisableTwoFactor disables 2FA for a user
func (s *twoFactorService) DisableTwoFactor(ctx context.Context, userID string) *types.GoAuthError {
	tfStorage := s.deps.Storage.TwoFactorAuth()

	// Use transaction to delete both 2FA config and backup codes atomically
	err := tfStorage.WithTransaction(ctx, func(tx types.TwoFactorStorage) error {
		// Delete 2FA config
		if err := tx.TwoFactor().Delete(ctx, userID); err != nil {
			return err
		}

		// Delete all backup codes
		if err := tx.BackupCodes().DeleteByUserID(ctx, userID); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		s.deps.Logger.Error("Failed to disable 2FA", "error", err)
		return types.NewInternalError("Failed to disable 2FA")
	}

	return nil
}

// GenerateBackupCodes generates backup codes (returns plain text for initial display)
func (s *twoFactorService) GenerateBackupCodes(ctx context.Context, userID string) ([]string, *types.GoAuthError) {
	plainCodes := make([]string, s.backupCodesCount)

	for i := 0; i < s.backupCodesCount; i++ {
		code, err := s.generateRandomCode(s.codeLength)
		if err != nil {
			s.deps.Logger.Error("Failed to generate backup code", "error", err)
			return nil, types.NewInternalError("Failed to generate backup codes")
		}
		plainCodes[i] = code
	}

	return plainCodes, nil
}

// SaveBackupCodes hashes and saves backup codes to database
func (s *twoFactorService) SaveBackupCodes(ctx context.Context, userID string, plainCodes []string) *types.GoAuthError {
	bcRepo := s.deps.Storage.TwoFactorAuth().BackupCodes()

	// First, delete any existing backup codes for this user
	if err := bcRepo.DeleteByUserID(ctx, userID); err != nil {
		s.deps.Logger.Error("Failed to delete old backup codes", "error", err)
		return types.NewInternalError("Failed to save backup codes")
	}

	// Hash and create backup code models
	backupCodes := make([]*models.BackupCode, len(plainCodes))
	for i, plainCode := range plainCodes {
		hashedCode, err := bcrypt.GenerateFromPassword([]byte(plainCode), bcrypt.DefaultCost)
		if err != nil {
			s.deps.Logger.Error("Failed to hash backup code", "error", err)
			return types.NewInternalError("Failed to save backup codes")
		}

		backupCodes[i] = &models.BackupCode{
			ID:     uuid.New().String(),
			UserID: userID,
			Code:   string(hashedCode),
			Used:   false,
		}
	}

	// Save batch
	if err := bcRepo.CreateBatch(ctx, backupCodes); err != nil {
		s.deps.Logger.Error("Failed to save backup codes", "error", err)
		return types.NewInternalError("Failed to save backup codes")
	}

	return nil
}

// UseBackupCode verifies and marks a backup code as used
func (s *twoFactorService) UseBackupCode(ctx context.Context, userID, plainCode string) *types.GoAuthError {
	bcRepo := s.deps.Storage.TwoFactorAuth().BackupCodes()

	// Get all unused backup codes
	backupCodes, err := bcRepo.GetUnusedByUserID(ctx, userID)
	if err != nil {
		s.deps.Logger.Error("Failed to get backup codes", "error", err)
		return types.NewInternalError("Failed to verify backup code")
	}

	if len(backupCodes) == 0 {
		return types.NewTwoFactorInvalidError()
	}

	// Try to match against hashed codes
	for _, bc := range backupCodes {
		err := bcrypt.CompareHashAndPassword([]byte(bc.Code), []byte(plainCode))
		if err == nil {
			// Match found! Mark as used
			if err := bcRepo.MarkUsed(ctx, bc.ID); err != nil {
				s.deps.Logger.Error("Failed to mark backup code as used", "error", err)
				return types.NewInternalError("Failed to use backup code")
			}
			return nil
		}
	}

	// No match found
	s.deps.Logger.Warn("Invalid backup code attempt", "user_id", userID)
	return types.NewTwoFactorInvalidError()
}

// VerifyCodeOrBackup tries TOTP first, then backup code
func (s *twoFactorService) VerifyCodeOrBackup(ctx context.Context, userID, code string) *types.GoAuthError {
	// Try TOTP first (6 digits)
	if len(code) == 6 {
		authErr := s.VerifyCode(ctx, userID, code)
		if authErr == nil {
			return nil // TOTP valid
		}
		// If not found error, return it immediately (user doesn't have 2FA)
		if authErr.Code == types.ErrTwoFactorNotFound {
			return authErr
		}
		// Otherwise, fall through to try backup code
	}

	// Try backup code (8+ characters, formatted XXXX-XXXX)
	if len(code) >= 8 {
		authErr := s.UseBackupCode(ctx, userID, code)
		if authErr == nil {
			// TODO: Emit event for backup code usage (user should regenerate)
			return nil
		}
	}

	return types.NewTwoFactorInvalidError()
}

// generateRandomCode generates a random alphanumeric code
func (s *twoFactorService) generateRandomCode(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	var code strings.Builder
	for _, v := range b {
		code.WriteByte(charset[int(v)%len(charset)])
	}

	// Format as XXXX-XXXX for 8-character codes
	if length == 8 {
		str := code.String()
		return fmt.Sprintf("%s-%s", str[:4], str[4:]), nil
	}

	return code.String(), nil
}

// VerifyCodeManual manually verifies TOTP code against secret (for setup flow)
// This is used during setup before 2FA is enabled
func (s *twoFactorService) VerifyCodeManual(ctx context.Context, secret, code string) *types.GoAuthError {
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil || !valid {
		return types.NewTwoFactorInvalidError()
	}

	return nil
}

// GetUser retrieves user by ID (delegates to core user repository)
func (s *twoFactorService) GetUser(ctx context.Context, userID string) (*models.User, *types.GoAuthError) {
	user, err := s.deps.Storage.Core().Users().FindByID(ctx, userID)
	if err != nil || user == nil {
		s.deps.Logger.Error("Failed to get user", "user_id", userID, "error", err)
		return nil, types.NewUserNotFoundError()
	}
	return user, nil
}

// IssueAuthTokenAfter2FA issues session or JWT tokens based on active auth module
// This method handles ALL repository access for token issuance
func (s *twoFactorService) IssueAuthTokenAfter2FA(ctx context.Context, user *models.User, metadata *types.RequestMetadata) (map[string]any, *types.GoAuthError) {
	// Try session-based auth first
	if sessionStorage := s.deps.Storage.Session(); sessionStorage != nil {
		return s.issueSessionToken(ctx, user, metadata, sessionStorage)
	}

	// Fall back to stateless auth
	if statelessStorage := s.deps.Storage.Stateless(); statelessStorage != nil {
		return s.issueStatelessToken(ctx, user, metadata, statelessStorage)
	}

	// Neither session nor stateless storage available - should never happen
	s.deps.Logger.Error("No auth storage available for token issuance")
	return nil, types.NewInternalError("Authentication system not properly configured")
}

// issueSessionToken creates a session and returns tokens (session-based auth)
func (s *twoFactorService) issueSessionToken(ctx context.Context, user *models.User, metadata *types.RequestMetadata, sessionStorage types.SessionStorage) (map[string]any, *types.GoAuthError) {
	sessionID := uuid.New().String()

	// Generate tokens with session_id in JWT claims
	accessToken, refreshToken, err := s.deps.SecurityManager.GenerateTokens(user, map[string]interface{}{
		"session_id": sessionID,
	})
	if err != nil {
		s.deps.Logger.Error("Failed to generate session tokens after 2FA", "error", err)
		return nil, types.NewInternalError("Failed to generate authentication tokens")
	}

	// Create session
	session := &models.Session{
		ID:                    sessionID,
		UserID:                user.ID,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: time.Now().Add(s.deps.Config.Security.Session.RefreshTokenTTL),
		ExpiresAt:             time.Now().Add(s.deps.Config.Security.Session.SessionTTL),
		UserAgent:             metadata.UserAgent,
		IPAddress:             metadata.IPAddress,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	if err := sessionStorage.Sessions().Create(ctx, session); err != nil {
		s.deps.Logger.Error("Failed to create session after 2FA", "error", err)
		return nil, types.NewInternalError("Failed to create session")
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.deps.Storage.Core().Users().Update(ctx, user); err != nil {
		s.deps.Logger.Warn("Failed to update user last login time", "error", err)
	}

	s.deps.Logger.Info("2FA login successful (session-based)", "user_id", user.ID, "session_id", sessionID)

	return map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"session_id":    sessionID,
		"user": map[string]any{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
		},
		"expires_in": int64(s.deps.Config.Security.Session.SessionTTL.Seconds()),
		"message":    "2FA verification successful - session created",
	}, nil
}

// issueStatelessToken generates JWT tokens with nonce-based refresh token (stateless auth)
func (s *twoFactorService) issueStatelessToken(ctx context.Context, user *models.User, metadata *types.RequestMetadata, statelessStorage types.StatelessStorage) (map[string]any, *types.GoAuthError) {
	// Generate access token
	accessToken, err := s.deps.SecurityManager.GenerateAccessToken(*user, map[string]interface{}{})
	if err != nil {
		s.deps.Logger.Error("Failed to generate access token after 2FA", "error", err)
		return nil, types.NewInternalError("Failed to generate authentication tokens")
	}

	// Generate stateless refresh token with JTI (nonce)
	refreshToken, jti, err := s.deps.SecurityManager.GenerateStatelessRefreshToken(user)
	if err != nil {
		s.deps.Logger.Error("Failed to generate refresh token after 2FA", "error", err)
		return nil, types.NewInternalError("Failed to generate authentication tokens")
	}

	// Store the JTI (nonce) in the tokens table for revocation checks
	tokenModel := &models.Token{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Type:      "refresh_nonce",
		Token:     jti,
		ExpiresAt: time.Now().Add(s.deps.Config.Security.Session.RefreshTokenTTL),
		CreatedAt: time.Now(),
	}
	if err := s.deps.Storage.Core().Tokens().Create(ctx, tokenModel); err != nil {
		s.deps.Logger.Error("Failed to save refresh token nonce after 2FA", "error", err)
		return nil, types.NewInternalError("Failed to complete authentication")
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.deps.Storage.Core().Users().Update(ctx, user); err != nil {
		s.deps.Logger.Warn("Failed to update user last login time", "error", err)
	}

	s.deps.Logger.Info("2FA login successful (stateless)", "user_id", user.ID)

	return map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": map[string]any{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
		},
		"expires_in": int64(s.deps.Config.Security.Session.SessionTTL.Seconds()),
		"message":    "2FA verification successful - tokens issued",
	}, nil
}
