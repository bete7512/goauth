package services

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/pquerna/otp/totp"
)

// EnableTwoFactor enables two-factor authentication for a user
func (s *AuthService) EnableTwoFactor(ctx context.Context, userID string, req *dto.EnableTwoFactorRequest) (*dto.TwoFactorSetupResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Check if 2FA is already enabled
	if user.TwoFactorEnabled != nil && *user.TwoFactorEnabled {
		return nil, errors.New("two-factor authentication is already enabled")
	}

	switch req.Method {
	case "totp":
		return s.enableTOTP(ctx, user)
	case "email":
		return s.enableEmail2FA(ctx, user)
	case "sms":
		return s.enableSMS2FA(ctx, user)
	default:
		return nil, errors.New("unsupported two-factor method")
	}
}

// enableTOTP enables TOTP-based two-factor authentication
func (s *AuthService) enableTOTP(ctx context.Context, user *models.User) (*dto.TwoFactorSetupResponse, error) {
	// Generate TOTP secret
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// Encrypt the secret before storing
	encryptedSecret, err := s.Auth.TokenManager.Encrypt(secretBase32)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Generate QR code URL
	qrCode := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		s.Auth.Config.App.Domain,
		user.Email,
		secretBase32,
		s.Auth.Config.App.Domain)

	// Generate backup codes
	backupCodes := make([]string, 8)
	backupCodeModels := make([]*models.BackupCode, 8)

	for i := 0; i < 8; i++ {
		code, err := s.Auth.TokenManager.GenerateRandomToken(8)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		backupCodes[i] = code

		// Hash the backup code
		hashedCode, err := s.Auth.TokenManager.HashToken(code)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}

		used := false
		backupCodeModels[i] = &models.BackupCode{
			UserID: user.ID,
			Code:   hashedCode,
			Used:   &used,
		}
	}

	// Save TOTP secret
	totpSecret := &models.TotpSecret{
		UserID:    user.ID,
		Secret:    encryptedSecret,
		BackupURL: qrCode,
		Verified:  nil, // Will be set to true after verification
	}

	if err := s.Auth.Repository.GetTotpSecretRepository().CreateTOTPSecret(ctx, totpSecret); err != nil {
		return nil, fmt.Errorf("failed to save TOTP secret: %w", err)
	}

	// Save backup codes
	if err := s.Auth.Repository.GetBackupCodeRepository().CreateBackupCodes(ctx, backupCodeModels); err != nil {
		return nil, fmt.Errorf("failed to save backup codes: %w", err)
	}

	return &dto.TwoFactorSetupResponse{
		Message:     "TOTP two-factor authentication setup initiated",
		Method:      "totp",
		QRCode:      qrCode,
		Secret:      secretBase32,
		BackupCodes: backupCodes,
	}, nil
}

// enableEmail2FA enables email-based two-factor authentication
func (s *AuthService) enableEmail2FA(ctx context.Context, user *models.User) (*dto.TwoFactorSetupResponse, error) {
	// Check if user has verified email
	if user.EmailVerified == nil || !*user.EmailVerified {
		return nil, errors.New("email must be verified before enabling email-based two-factor authentication")
	}

	// Generate verification code
	code, err := s.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification code: %w", err)
	}

	// Hash the code
	hashedCode, err := s.Auth.TokenManager.HashToken(code)
	if err != nil {
		return nil, fmt.Errorf("failed to hash verification code: %w", err)
	}

	// Save verification token
	expiresAt := time.Now().Add(s.Auth.Config.AuthConfig.Tokens.TwoFactorTTL)
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedCode, models.TwoFactorCode, s.Auth.Config.AuthConfig.Tokens.TwoFactorTTL); err != nil {
		return nil, fmt.Errorf("failed to save verification token: %w", err)
	}

	// Send verification email
	if s.Auth.EmailSender != nil {
		if err := s.Auth.EmailSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
			return nil, fmt.Errorf("failed to send verification email: %w", err)
		}
	}

	return &dto.TwoFactorSetupResponse{
		Message:   "Email verification code sent",
		Method:    "email",
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}, nil
}

// enableSMS2FA enables SMS-based two-factor authentication
func (s *AuthService) enableSMS2FA(ctx context.Context, user *models.User) (*dto.TwoFactorSetupResponse, error) {
	// Check if user has verified phone
	if user.PhoneVerified == nil || !*user.PhoneVerified {
		return nil, errors.New("phone number must be verified before enabling SMS-based two-factor authentication")
	}

	// Check if user has phone number
	if user.PhoneNumber == nil || *user.PhoneNumber == "" {
		return nil, errors.New("phone number is required for SMS-based two-factor authentication")
	}

	// Generate verification code
	code, err := s.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification code: %w", err)
	}

	// Hash the code
	hashedCode, err := s.Auth.TokenManager.HashToken(code)
	if err != nil {
		return nil, fmt.Errorf("failed to hash verification code: %w", err)
	}

	// Save verification token
	expiresAt := time.Now().Add(s.Auth.Config.AuthConfig.Tokens.TwoFactorTTL)
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedCode, models.TwoFactorCode, s.Auth.Config.AuthConfig.Tokens.TwoFactorTTL); err != nil {
		return nil, fmt.Errorf("failed to save verification token: %w", err)
	}

	// Send verification SMS
	if s.Auth.EmailSender != nil { // Assuming SMS sender is available through email sender interface
		if err := s.Auth.EmailSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
			return nil, fmt.Errorf("failed to send verification SMS: %w", err)
		}
	}

	return &dto.TwoFactorSetupResponse{
		Message:   "SMS verification code sent",
		Method:    "sms",
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}, nil
}

// VerifyTwoFactorSetup verifies the two-factor authentication setup
func (s *AuthService) VerifyTwoFactorSetup(ctx context.Context, userID string, req *dto.VerifyTwoFactorSetupRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Get the verification token
	token, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, userID, models.TwoFactorCode)
	if err != nil || token == nil {
		return errors.New("verification code not found or expired")
	}

	// Verify the code
	hashedCode, err := s.Auth.TokenManager.HashToken(req.Code)
	if err != nil {
		return fmt.Errorf("failed to hash verification code: %w", err)
	}

	if hashedCode != token.TokenValue {
		return errors.New("invalid verification code")
	}

	// Enable 2FA
	twoFactorEnabled := true
	user.TwoFactorEnabled = &twoFactorEnabled
	user.UpdatedAt = time.Now()

	// Update enabled methods based on the action type
	if token.ActionType == "enable_2fa_email" {
		user.DefaultTwoFactorMethod = models.TwoFactorMethodEmail
	} else if token.ActionType == "enable_2fa_sms" {
		user.DefaultTwoFactorMethod = models.TwoFactorMethodSMS
	} else {
		user.DefaultTwoFactorMethod = models.TwoFactorMethodTOTP
	}

	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to enable two-factor authentication: %w", err)
	}

	// Mark TOTP secret as verified if it's TOTP setup
	if user.DefaultTwoFactorMethod == models.TwoFactorMethodTOTP {
		totpSecret, err := s.Auth.Repository.GetTotpSecretRepository().GetTOTPSecretByUserID(ctx, userID)
		if err == nil && totpSecret != nil {
			verified := true
			totpSecret.Verified = &verified
			if err := s.Auth.Repository.GetTotpSecretRepository().UpdateTOTPSecret(ctx, totpSecret); err != nil {
				return fmt.Errorf("failed to mark TOTP secret as verified: %w", err)
			}
		}
	}

	// Revoke the verification token
	if err := s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, token.ID); err != nil {
		return fmt.Errorf("failed to revoke verification token: %w", err)
	}

	return nil
}

// VerifyTwoFactor verifies two-factor authentication code
func (s *AuthService) VerifyTwoFactor(ctx context.Context, userID string, req *dto.TwoFactorVerificationRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		return errors.New("two-factor authentication is not enabled")
	}

	// Determine verification method
	method := req.Method
	if method == "" {
		method = string(user.DefaultTwoFactorMethod)
	}

	switch method {
	case "totp":
		return s.verifyTOTP(ctx, user, req.Code)
	case "email":
		return s.verifyEmail2FA(ctx, user, req.Code)
	case "sms":
		return s.verifySMS2FA(ctx, user, req.Code)
	case "backup":
		return s.verifyBackupCode(ctx, user, req.Code)
	default:
		return errors.New("unsupported verification method")
	}
}

// verifyTOTP verifies TOTP code
func (s *AuthService) verifyTOTP(ctx context.Context, user *models.User, code string) error {
	totpSecret, err := s.Auth.Repository.GetTotpSecretRepository().GetTOTPSecretByUserID(ctx, user.ID)
	if err != nil || totpSecret == nil {
		return errors.New("TOTP secret not found")
	}

	if totpSecret.Verified == nil || !*totpSecret.Verified {
		return errors.New("TOTP secret not verified")
	}

	// Decrypt the secret
	decryptedSecret, err := s.Auth.TokenManager.Decrypt(totpSecret.Secret)
	if err != nil {
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// Verify TOTP code
	if !totp.Validate(code, decryptedSecret) {
		return errors.New("invalid TOTP code")
	}

	return nil
}

// verifyEmail2FA verifies email-based 2FA code
func (s *AuthService) verifyEmail2FA(ctx context.Context, user *models.User, code string) error {
	token, err := s.Auth.Repository.GetTokenRepository().GetActiveTokenByUserIdAndType(ctx, user.ID, models.TwoFactorCode)
	if err != nil || token == nil {
		return errors.New("verification code not found or expired")
	}

	// Verify the code
	hashedCode, err := s.Auth.TokenManager.HashToken(code)
	if err != nil {
		return fmt.Errorf("failed to hash verification code: %w", err)
	}

	if hashedCode != token.TokenValue {
		return errors.New("invalid verification code")
	}

	// Revoke the token after successful verification
	if err := s.Auth.Repository.GetTokenRepository().RevokeToken(ctx, token.ID); err != nil {
		return fmt.Errorf("failed to revoke verification token: %w", err)
	}

	return nil
}

// verifySMS2FA verifies SMS-based 2FA code
func (s *AuthService) verifySMS2FA(ctx context.Context, user *models.User, code string) error {
	// Same logic as email verification
	return s.verifyEmail2FA(ctx, user, code)
}

// verifyBackupCode verifies backup code
func (s *AuthService) verifyBackupCode(ctx context.Context, user *models.User, code string) error {
	backupCodes, err := s.Auth.Repository.GetBackupCodeRepository().GetBackupCodeByUserID(ctx, user.ID)
	if err != nil || backupCodes == nil {
		return errors.New("backup codes not found")
	}

	// Hash the provided code
	hashedCode, err := s.Auth.TokenManager.HashToken(code)
	if err != nil {
		return fmt.Errorf("failed to hash backup code: %w", err)
	}

	// Check if the code matches and is not used
	if hashedCode == backupCodes.Code && (backupCodes.Used == nil || !*backupCodes.Used) {
		// Mark the backup code as used
		used := true
		now := time.Now()
		backupCodes.Used = &used
		backupCodes.UsedAt = &now

		if err := s.Auth.Repository.GetBackupCodeRepository().UpdateBackupCode(ctx, backupCodes); err != nil {
			return fmt.Errorf("failed to mark backup code as used: %w", err)
		}

		return nil
	}

	return errors.New("invalid or used backup code")
}

// ResendTwoFactorCode resends two-factor authentication code
func (s *AuthService) ResendTwoFactorCode(ctx context.Context, userID string, req *dto.ResendTwoFactorCodeRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		return errors.New("two-factor authentication is not enabled")
	}

	// Revoke existing tokens
	if err := s.Auth.Repository.GetTokenRepository().RevokeAllTokens(ctx, userID, models.TwoFactorCode); err != nil {
		return fmt.Errorf("failed to revoke existing tokens: %w", err)
	}

	switch req.Method {
	case "email":
		return s.sendEmail2FACode(ctx, user)
	case "sms":
		return s.sendSMS2FACode(ctx, user)
	default:
		return errors.New("unsupported method")
	}
}

// sendEmail2FACode sends email-based 2FA code
func (s *AuthService) sendEmail2FACode(ctx context.Context, user *models.User) error {
	// Generate verification code
	code, err := s.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate verification code: %w", err)
	}

	// Hash the code
	hashedCode, err := s.Auth.TokenManager.HashToken(code)
	if err != nil {
		return fmt.Errorf("failed to hash verification code: %w", err)
	}

	// Save verification token
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedCode, models.TwoFactorCode, s.Auth.Config.AuthConfig.Tokens.TwoFactorTTL); err != nil {
		return fmt.Errorf("failed to save verification token: %w", err)
	}

	// Send verification email
	if s.Auth.EmailSender != nil {
		if err := s.Auth.EmailSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
			return fmt.Errorf("failed to send verification email: %w", err)
		}
	}

	return nil
}

// sendSMS2FACode sends SMS-based 2FA code
func (s *AuthService) sendSMS2FACode(ctx context.Context, user *models.User) error {
	// Generate verification code
	code, err := s.Auth.TokenManager.GenerateNumericOTP(6)
	if err != nil {
		return fmt.Errorf("failed to generate verification code: %w", err)
	}

	// Hash the code
	hashedCode, err := s.Auth.TokenManager.HashToken(code)
	if err != nil {
		return fmt.Errorf("failed to hash verification code: %w", err)
	}

	// Save verification token
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, user.ID, hashedCode, models.TwoFactorCode, s.Auth.Config.AuthConfig.Tokens.TwoFactorTTL); err != nil {
		return fmt.Errorf("failed to save verification token: %w", err)
	}

	// Send verification SMS (assuming SMS sender is available)
	if s.Auth.EmailSender != nil {
		if err := s.Auth.EmailSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
			return fmt.Errorf("failed to send verification SMS: %w", err)
		}
	}

	return nil
}

// GetTwoFactorStatus gets the two-factor authentication status
func (s *AuthService) GetTwoFactorStatus(ctx context.Context, userID string) (*dto.TwoFactorStatusResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	enabled := user.TwoFactorEnabled != nil && *user.TwoFactorEnabled
	methods := []string{}

	if enabled {
		// Check which methods are available
		if user.EmailVerified != nil && *user.EmailVerified {
			methods = append(methods, "email")
		}
		if user.PhoneVerified != nil && *user.PhoneVerified && user.PhoneNumber != nil && *user.PhoneNumber != "" {
			methods = append(methods, "sms")
		}

		// Check if TOTP is set up
		totpSecret, err := s.Auth.Repository.GetTotpSecretRepository().GetTOTPSecretByUserID(ctx, userID)
		if err == nil && totpSecret != nil && totpSecret.Verified != nil && *totpSecret.Verified {
			methods = append(methods, "totp")
		}
	}

	return &dto.TwoFactorStatusResponse{
		Enabled: enabled,
		Methods: methods,
	}, nil
}

// TwoFactorLogin handles two-factor authentication during login
func (s *AuthService) TwoFactorLogin(ctx context.Context, req *dto.TwoFactorLoginRequest) (*dto.LoginResponse, error) {
	// First, verify email and password
	user, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if user is active
	if user.Active != nil && !*user.Active {
		return nil, errors.New("account is deactivated")
	}

	// Verify password
	if err := s.Auth.TokenManager.ValidatePassword(user.Password, req.Password); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		return nil, errors.New("two-factor authentication is not enabled")
	}

	// Verify 2FA code
	verificationReq := &dto.TwoFactorVerificationRequest{
		Code:   req.Code,
		Method: req.Method,
	}
	if err := s.VerifyTwoFactor(ctx, user.ID, verificationReq); err != nil {
		return nil, fmt.Errorf("two-factor verification failed: %w", err)
	}

	// Generate tokens
	accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		s.Auth.Logger.Errorf("Failed to update last login: %v", err)
	}

	return &dto.LoginResponse{
		Message: "login successful",
		User:    s.mapUserToDTO(user),
		Tokens: dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}

// DisableTwoFactor disables two-factor authentication for a user
func (s *AuthService) DisableTwoFactor(ctx context.Context, userID string, req *dto.DisableTwoFactorRequest) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		return errors.New("two-factor authentication is not enabled")
	}

	// Verify password
	if err := s.Auth.TokenManager.ValidatePassword(user.Password, req.Password); err != nil {
		return errors.New("invalid password")
	}

	// Disable 2FA
	twoFactorEnabled := false
	user.TwoFactorEnabled = &twoFactorEnabled
	user.UpdatedAt = time.Now()

	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to disable two-factor authentication: %w", err)
	}

	// Clean up TOTP secrets
	if err := s.Auth.Repository.GetTotpSecretRepository().DeleteTOTPSecret(ctx, &models.TotpSecret{UserID: userID}); err != nil {
		s.Auth.Logger.Errorf("Failed to clean up TOTP secrets: %v", err)
	}

	// Clean up backup codes
	if err := s.Auth.Repository.GetBackupCodeRepository().DeleteBackupCode(ctx, &models.BackupCode{UserID: userID}); err != nil {
		s.Auth.Logger.Errorf("Failed to clean up backup codes: %v", err)
	}

	// Revoke all 2FA tokens
	if err := s.Auth.Repository.GetTokenRepository().RevokeAllTokens(ctx, userID, models.TwoFactorCode); err != nil {
		s.Auth.Logger.Errorf("Failed to revoke 2FA tokens: %v", err)
	}

	return nil
}
