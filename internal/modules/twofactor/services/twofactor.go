package services

//go:generate mockgen -destination=../../../mocks/mock_twofactor_service.go -package=mocks github.com/bete7512/goauth/internal/modules/twofactor/services TwoFactorService

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/bete7512/goauth/internal/authentication"
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
		return "", "", types.NewInternalError("Failed to generate 2FA secret").Wrap(err)
	}

	return key.Secret(), key.URL(), nil
}

// SaveTwoFactorConfig saves or updates 2FA configuration
func (s *twoFactorService) SaveTwoFactorConfig(ctx context.Context, tfConfig *models.TwoFactor) *types.GoAuthError {
	copy := *tfConfig
	tfConfig = &copy
	encrypted, encryptionErr := s.deps.SecurityManager.Encrypt(tfConfig.Secret)
	if encryptionErr != nil {
		return types.NewInternalError("failed to encrypt two-factor secret").Wrap(encryptionErr)
	}
	tfConfig.Secret = encrypted
	tfRepo := s.deps.Storage.TwoFactorAuth().TwoFactor()

	// Check if config already exists
	existing, err := tfRepo.GetByUserID(ctx, tfConfig.UserID)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		s.deps.Logger.Error("Failed to check existing 2FA config", "error", err)
		return types.NewInternalError("Failed to save 2FA configuration").Wrap(err)
	}

	if existing != nil {
		// Update existing
		tfConfig.ID = existing.ID
		tfConfig.CreatedAt = existing.CreatedAt
		if err := tfRepo.Update(ctx, tfConfig); err != nil {
			s.deps.Logger.Error("Failed to update 2FA config", "error", err)
			return types.NewInternalError("Failed to update 2FA configuration").Wrap(err)
		}
	} else {
		// Create new
		tfConfig.ID = uuid.Must(uuid.NewV7()).String()
		if err := tfRepo.Create(ctx, tfConfig); err != nil {
			s.deps.Logger.Error("Failed to create 2FA config", "error", err)
			return types.NewInternalError("Failed to save 2FA configuration").Wrap(err)
		}
	}

	return nil
}

// GetTwoFactorConfig retrieves 2FA configuration for a user
func (s *twoFactorService) GetTwoFactorConfig(ctx context.Context, userID string) (*models.TwoFactor, *types.GoAuthError) {
	tfRepo := s.deps.Storage.TwoFactorAuth().TwoFactor()

	tfConfig, err := tfRepo.GetByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewTwoFactorNotFoundError()
		}
		s.deps.Logger.Error("Failed to get 2FA config", "error", err)
		return nil, types.NewInternalError("Failed to retrieve 2FA configuration").Wrap(err)
	}

	// Legacy plaintext records remain readable and are encrypted on the next
	// write. Versioned records must decrypt successfully; never fall back on error.
	if strings.HasPrefix(tfConfig.Secret, "v1.") {
		secret, err := s.deps.SecurityManager.Decrypt(tfConfig.Secret)
		if err != nil {
			return nil, types.NewInternalError("two-factor key unavailable").Wrap(err)
		}
		copy := *tfConfig
		tfConfig = &copy
		tfConfig.Secret = secret
	}
	return tfConfig, nil
}

// maxTwoFactorAttempts is the number of failed 2FA attempts before lockout.
const maxTwoFactorAttempts = 5

// twoFactorLockoutDuration is how long 2FA stays locked after too many failures.
const twoFactorLockoutDuration = 15 * time.Minute

// VerifyCode verifies a TOTP code with brute-force rate limiting
func (s *twoFactorService) VerifyCode(ctx context.Context, userID, code string) *types.GoAuthError {
	// Get 2FA config
	tfConfig, authErr := s.GetTwoFactorConfig(ctx, userID)
	if authErr != nil {
		return authErr
	}

	if !tfConfig.Enabled {
		return types.NewTwoFactorNotEnabledError()
	}

	// Check if 2FA is locked due to too many failed attempts
	if tfConfig.LockedUntil != nil && tfConfig.LockedUntil.After(time.Now()) {
		s.deps.Logger.Warn("2FA verification blocked - account locked", "user_id", userID)
		return types.NewAccountLockedError()
	}

	// Verify TOTP code with time window tolerance (±1 period = 60s total window)
	valid, err := totp.ValidateCustom(code, tfConfig.Secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // Allow ±1 time window (30s before and after)
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil || !valid {
		// Increment failed attempts and potentially lock
		tfConfig.FailedAttempts++
		if tfConfig.FailedAttempts >= maxTwoFactorAttempts {
			lockUntil := time.Now().Add(twoFactorLockoutDuration)
			tfConfig.LockedUntil = &lockUntil
			s.deps.Logger.Warn("2FA locked due to too many failed attempts", "user_id", userID, "attempts", tfConfig.FailedAttempts)
		}
		if updateErr := s.SaveTwoFactorConfig(ctx, tfConfig); updateErr != nil {
			s.deps.Logger.Error("Failed to update 2FA failed attempts", "error", updateErr)
		}

		s.deps.Logger.Warn("Invalid 2FA code attempt", "user_id", userID, "attempts", tfConfig.FailedAttempts)
		return types.NewTwoFactorInvalidError()
	}

	// On success: reset failed attempts and lockout
	if tfConfig.FailedAttempts > 0 || tfConfig.LockedUntil != nil {
		tfConfig.FailedAttempts = 0
		tfConfig.LockedUntil = nil
		if updateErr := s.SaveTwoFactorConfig(ctx, tfConfig); updateErr != nil {
			s.deps.Logger.Error("Failed to reset 2FA failed attempts", "error", updateErr)
		}
	}

	return nil
}

// EnableTwoFactor enables 2FA for a user
func (s *twoFactorService) EnableTwoFactor(ctx context.Context, userID string) *types.GoAuthError {
	tfConfig, authErr := s.GetTwoFactorConfig(ctx, userID)
	if authErr != nil {
		return authErr
	}

	tfConfig.Enabled = true
	tfConfig.Verified = true

	if err := s.SaveTwoFactorConfig(ctx, tfConfig); err != nil {
		s.deps.Logger.Error("Failed to enable 2FA", "error", err)
		return types.NewInternalError("Failed to enable 2FA").Wrap(err)
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
		return types.NewInternalError("Failed to disable 2FA").Wrap(err)
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
			return nil, types.NewInternalError("Failed to generate backup codes").Wrap(err)
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
		return types.NewInternalError("Failed to save backup codes").Wrap(err)
	}

	// Hash and create backup code models
	backupCodes := make([]*models.BackupCode, len(plainCodes))
	for i, plainCode := range plainCodes {
		hashedCode, err := bcrypt.GenerateFromPassword([]byte(plainCode), bcrypt.DefaultCost)
		if err != nil {
			s.deps.Logger.Error("Failed to hash backup code", "error", err)
			return types.NewInternalError("Failed to save backup codes").Wrap(err)
		}

		backupCodes[i] = &models.BackupCode{
			ID:     uuid.Must(uuid.NewV7()).String(),
			UserID: userID,
			Code:   string(hashedCode),
			Used:   false,
		}
	}

	// Save batch
	if err := bcRepo.CreateBatch(ctx, backupCodes); err != nil {
		s.deps.Logger.Error("Failed to save backup codes", "error", err)
		return types.NewInternalError("Failed to save backup codes").Wrap(err)
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
		return types.NewInternalError("Failed to verify backup code").Wrap(err)
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
				return types.NewInternalError("Failed to use backup code").Wrap(err)
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
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		s.deps.Logger.Error("Failed to get user", "user_id", userID, "error", err)
		return nil, types.NewInternalError("failed to get user").Wrap(err)
	}
	return user, nil
}

// IssueAuthTokenAfter2FA issues session or JWT tokens based on active auth module
// This method handles ALL repository access for token issuance
func (s *twoFactorService) IssueAuthTokenAfter2FA(ctx context.Context, user *models.User, metadata *types.RequestMetadata) (map[string]any, *types.GoAuthError) {
	var sessions models.SessionRepository
	if s.deps.Storage.Session() != nil {
		sessions = s.deps.Storage.Session().Sessions()
	}
	completion := authentication.ForModule(s.deps, s.deps.Storage.Core().Tokens(), sessions, "")
	result, authErr := completion.Complete(ctx, types.AuthenticationEvidence{User: user, Method: "mfa", Phase: types.PhaseResume, Metadata: metadata})
	if authErr != nil {
		return nil, authErr
	}
	if result.Status == types.ChallengeRequired {
		return map[string]any{"challenges": result.Challenges}, nil
	}
	return map[string]any{"access_token": result.AccessToken, "refresh_token": result.RefreshToken, "session_id": result.SessionID, "expires_in": result.ExpiresIn, "user": map[string]any{"id": user.ID, "email": user.Email, "name": user.Name}}, nil
}
