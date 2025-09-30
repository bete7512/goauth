package twofactor_service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/pquerna/otp/totp"
)

// EnableTwoFactor enables two-factor authentication for a user
func (s *TwoFactorService) EnableTwoFactor(ctx context.Context, userID string, req *dto.EnableTwoFactorRequest) (*dto.TwoFactorSetupResponse, *types.GoAuthError) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		s.logger.Errorf("failed to get user by id: %v", err)
		return nil, types.NewUserNotFoundError()
	}

	// Check if 2FA is already enabled
	if user.TwoFactorEnabled != nil && *user.TwoFactorEnabled {
		s.logger.Errorf("two-factor authentication is already enabled")
		return nil, types.NewTwoFactorAlreadyEnabledError()
	}

	switch req.Method {
	case "totp":
		return s.enableTOTP(ctx, user)
	case "email":
		return s.enableEmail2FA(ctx, user)
	case "sms":
		return s.enableSMS2FA(ctx, user)
	default:
		return nil, types.NewCustomError("unsupported two-factor method")
	}
}

// enableTOTP enables TOTP-based two-factor authentication
func (s *TwoFactorService) enableTOTP(ctx context.Context, user *models.User) (*dto.TwoFactorSetupResponse, *types.GoAuthError) {
	// Generate TOTP secret
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		s.logger.Errorf("failed to generate TOTP secret: %v", err)
		return nil, types.NewInternalError(err.Error())
	}
	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// Encrypt the secret before storing
	encryptedSecret, err := s.tokenMgr.Encrypt(secretBase32)
	if err != nil {
		s.logger.Errorf("failed to encrypt TOTP secret: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Generate QR code URL
	qrCode := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		s.config.App.Domain,
		user.Email,
		secretBase32,
		s.config.App.Domain)

	// Generate backup codes
	backupCodes := make([]string, 8)
	backupCodeModels := make([]*models.BackupCode, 8)

	for i := 0; i < 8; i++ {
		code, err := s.tokenMgr.GenerateRandomToken(8)
		if err != nil {
			s.logger.Errorf("failed to generate backup code: %v", err)
			return nil, types.NewInternalError(err.Error())
		}
		backupCodes[i] = code

		// Hash the backup code
		hashedCode, err := s.tokenMgr.HashToken(code)
		if err != nil {
			s.logger.Errorf("failed to hash backup code: %v", err)
			return nil, types.NewInternalError(err.Error())
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

	if err := s.tokenRepo.CreateTOTPSecret(ctx, totpSecret); err != nil {
		s.logger.Errorf("failed to save TOTP secret: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Save backup codes
	if err := s.tokenRepo.CreateBackupCodes(ctx, backupCodeModels); err != nil {
		s.logger.Errorf("failed to save backup codes: %v", err)
		return nil, types.NewInternalError(err.Error())
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
func (s *TwoFactorService) enableEmail2FA(ctx context.Context, user *models.User) (*dto.TwoFactorSetupResponse, *types.GoAuthError) {
	// Check if user has verified email
	if user.EmailVerified == nil || !*user.EmailVerified {
		s.logger.Errorf("email must be verified before enabling email-based two-factor authentication")
		return nil, types.NewEmailNotVerifiedError()
	}

	// Generate verification code
	code, err := s.tokenMgr.GenerateNumericOTP(6)
	if err != nil {
		s.logger.Errorf("failed to generate verification code: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Hash the code
	hashedCode, err := s.tokenMgr.HashToken(code)
	if err != nil {
		s.logger.Errorf("failed to hash verification code: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Save verification token
	expiresAt := time.Now().Add(s.config.AuthConfig.Tokens.TwoFactorTTL)
	if err := s.tokenRepo.SaveToken(ctx, user.ID, hashedCode, models.TwoFactorCode, s.config.AuthConfig.Tokens.TwoFactorTTL); err != nil {
		s.logger.Errorf("failed to save verification token: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Send verification email
	if s.config.Email.CustomSender != nil {
		if err := s.config.Email.CustomSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
			s.logger.Errorf("failed to send verification email: %v", err)
			return nil, types.NewEmailSendFailedError()
		}
	}

	return &dto.TwoFactorSetupResponse{
		Message:   "Email verification code sent",
		Method:    "email",
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}, nil
}

// enableSMS2FA enables SMS-based two-factor authentication
func (s *TwoFactorService) enableSMS2FA(ctx context.Context, user *models.User) (*dto.TwoFactorSetupResponse, *types.GoAuthError) {
	// Check if user has verified phone
	if user.PhoneVerified == nil || !*user.PhoneVerified {
		s.logger.Errorf("phone number must be verified before enabling SMS-based two-factor authentication")
		return nil, types.NewPhoneNotVerifiedError()
	}

	// Check if user has phone number
	if user.PhoneNumber == nil || *user.PhoneNumber == "" {
		s.logger.Errorf("phone number is required for SMS-based two-factor authentication")
		return nil, types.NewMissingFieldsError("phone number")
	}

	// Generate verification code
	code, err := s.tokenMgr.GenerateNumericOTP(6)
	if err != nil {
		s.logger.Errorf("failed to generate verification code: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Hash the code
	hashedCode, err := s.tokenMgr.HashToken(code)
	if err != nil {
		s.logger.Errorf("failed to hash verification code: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Save verification token
	expiresAt := time.Now().Add(s.config.AuthConfig.Tokens.TwoFactorTTL)
	if err := s.tokenRepo.SaveToken(ctx, user.ID, hashedCode, models.TwoFactorCode, s.config.AuthConfig.Tokens.TwoFactorTTL); err != nil {
		s.logger.Errorf("failed to save verification token: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Send verification SMS
	if s.config.Email.CustomSender != nil { // Assuming SMS sender is available through email sender interface
		if err := s.config.Email.CustomSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
			s.logger.Errorf("failed to send verification SMS: %v", err)
			return nil, types.NewSmsSendFailedError()
		}
	}

	return &dto.TwoFactorSetupResponse{
		Message:   "SMS verification code sent",
		Method:    "sms",
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}, nil
}

// VerifyTwoFactorSetup verifies the two-factor authentication setup
func (s *TwoFactorService) VerifyTwoFactorSetup(ctx context.Context, userID string, req *dto.VerifyTwoFactorSetupRequest) *types.GoAuthError {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		s.logger.Errorf("user not found")
		return types.NewUserNotFoundError()
	}

	// Get the verification token
	token, err := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, userID, models.TwoFactorCode)
	if err != nil || token == nil {
		s.logger.Errorf("verification code not found or expired")
		return types.NewTokenNotFoundError()
	}

	// Verify the code
	hashedCode, err := s.tokenMgr.HashToken(req.Code)
	if err != nil {
		s.logger.Errorf("failed to hash verification code: %v", err)
		return types.NewInternalError(err.Error())
	}

	if hashedCode != token.TokenValue {
		s.logger.Errorf("invalid verification code")
		return types.NewInvalidTokenError()
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

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Errorf("failed to enable two-factor authentication: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Mark TOTP secret as verified if it's TOTP setup
	if user.DefaultTwoFactorMethod == models.TwoFactorMethodTOTP {
		totpSecret, err := s.tokenRepo.GetTOTPSecretByUserID(ctx, userID)
		if err == nil && totpSecret != nil {
			verified := true
			totpSecret.Verified = &verified
			if err := s.tokenRepo.UpdateTOTPSecret(ctx, totpSecret); err != nil {
				s.logger.Errorf("failed to mark TOTP secret as verified: %v", err)
				return err
			}
		}
	}

	// Revoke the verification token
	if err := s.tokenRepo.RevokeToken(ctx, token.ID); err != nil {
		s.logger.Errorf("failed to revoke verification token: %v", err)
		return types.NewInternalError(err.Error())
	}

	return nil
}

// VerifyTwoFactor verifies two-factor authentication code
func (s *TwoFactorService) VerifyTwoFactor(ctx context.Context, userID string, req *dto.TwoFactorVerificationRequest) *types.GoAuthError {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		s.logger.Errorf("user not found")
		return types.NewUserNotFoundError()
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		s.logger.Errorf("two-factor authentication is not enabled")
		return types.NewTwoFactorNotEnabledError()
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
		s.logger.Errorf("unsupported verification method")
		return types.NewCustomError("unsupported verification method")
	}
}

// verifyTOTP verifies TOTP code
func (s *TwoFactorService) verifyTOTP(ctx context.Context, user *models.User, code string) *types.GoAuthError {
	totpSecret, err := s.tokenRepo.GetTOTPSecretByUserID(ctx, user.ID)
	if err != nil || totpSecret == nil {
		s.logger.Errorf("TOTP secret not found")
		return types.NewTokenNotFoundError()
	}

	if totpSecret.Verified == nil || !*totpSecret.Verified {
		s.logger.Errorf("TOTP secret not verified")
		return types.NewInvalidTokenError()
	}

	// Decrypt the secret
	decryptedSecret, err := s.tokenMgr.Decrypt(totpSecret.Secret)
	if err != nil {
		s.logger.Errorf("failed to decrypt TOTP secret: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Verify TOTP code
	if !totp.Validate(code, decryptedSecret) {
		s.logger.Errorf("invalid TOTP code")
		return types.NewInvalidTokenError()
	}

	return nil
}

// verifyEmail2FA verifies email-based 2FA code
func (s *TwoFactorService) verifyEmail2FA(ctx context.Context, user *models.User, code string) *types.GoAuthError {
	token, err := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, user.ID, models.TwoFactorCode)
	if err != nil || token == nil {
		s.logger.Errorf("verification code not found or expired")
		return types.NewTokenNotFoundError()
	}

	// Verify the code
	hashedCode, err := s.tokenMgr.HashToken(code)
	if err != nil {
		s.logger.Errorf("failed to hash verification code: %v", err)
		return types.NewInternalError(err.Error())
	}

	if hashedCode != token.TokenValue {
		s.logger.Errorf("invalid verification code")
		return types.NewInvalidTokenError()
	}

	// Revoke the token after successful verification
	if err := s.tokenRepo.RevokeToken(ctx, token.ID); err != nil {
		s.logger.Errorf("failed to revoke verification token: %v", err)
		return types.NewInternalError(err.Error())
	}

	return nil
}

// verifySMS2FA verifies SMS-based 2FA code
func (s *TwoFactorService) verifySMS2FA(ctx context.Context, user *models.User, code string) *types.GoAuthError {
	// Same logic as email verification
	return s.verifyEmail2FA(ctx, user, code)
}

// verifyBackupCode verifies backup code
func (s *TwoFactorService) verifyBackupCode(ctx context.Context, user *models.User, code string) *types.GoAuthError {
	backupCodes, err := s.tokenRepo.GetBackupCodeByUserID(ctx, user.ID)
	if err != nil || backupCodes == nil {
		s.logger.Errorf("backup codes not found")
		return types.NewTokenNotFoundError()
	}

	// Hash the provided code
	hashedCode, err := s.tokenMgr.HashToken(code)
	if err != nil {
		s.logger.Errorf("failed to hash backup code: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Check if the code matches and is not used
	if hashedCode == backupCodes.Code && (backupCodes.Used == nil || !*backupCodes.Used) {
		// Mark the backup code as used
		used := true
		now := time.Now()
		backupCodes.Used = &used
		backupCodes.UsedAt = &now

		if err := s.tokenRepo.UpdateBackupCode(ctx, backupCodes); err != nil {
			s.logger.Errorf("failed to mark backup code as used: %v", err)
			return types.NewInternalError(err.Error())
		}

		return nil
	}

	s.logger.Errorf("invalid or used backup code")
	return types.NewInvalidTokenError()
}

// ResendTwoFactorCode resends two-factor authentication code
func (s *TwoFactorService) ResendTwoFactorCode(ctx context.Context, userID string, req *dto.ResendTwoFactorCodeRequest) *types.GoAuthError {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		s.logger.Errorf("user not found")
		return types.NewUserNotFoundError()
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		s.logger.Errorf("two-factor authentication is not enabled")
		return types.NewTwoFactorNotEnabledError()
	}

	// Revoke existing tokens
	if err := s.tokenRepo.RevokeAllTokens(ctx, userID, models.TwoFactorCode); err != nil {
		s.logger.Errorf("failed to revoke existing tokens: %v", err)
		return types.NewInternalError(err.Error())
	}

	switch req.Method {
	case "email":
		return s.sendEmail2FACode(ctx, user)
	case "sms":
		return s.sendSMS2FACode(ctx, user)
	default:
		s.logger.Errorf("unsupported method")
		return types.NewCustomError("unsupported method")
	}
}

// sendEmail2FACode sends email-based 2FA code
func (s *TwoFactorService) sendEmail2FACode(ctx context.Context, user *models.User) *types.GoAuthError {
	// Generate verification code
	code, err := s.tokenMgr.GenerateNumericOTP(6)
	if err != nil {
		s.logger.Errorf("failed to generate verification code: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Hash the code
	hashedCode, err := s.tokenMgr.HashToken(code)
	if err != nil {
		s.logger.Errorf("failed to hash verification code: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Save verification token
	if err := s.tokenRepo.SaveToken(ctx, user.ID, hashedCode, models.TwoFactorCode, s.config.AuthConfig.Tokens.TwoFactorTTL); err != nil {
		s.logger.Errorf("failed to save verification token: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Send verification email
	if s.config.Email.CustomSender != nil {
		if err := s.config.Email.CustomSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
			s.logger.Errorf("failed to send verification email: %v", err)
			return types.NewEmailSendFailedError()
		}
	}

	return nil
}

// sendSMS2FACode sends SMS-based 2FA code
func (s *TwoFactorService) sendSMS2FACode(ctx context.Context, user *models.User) *types.GoAuthError {
	// Generate verification code
	code, err := s.tokenMgr.GenerateNumericOTP(6)
	if err != nil {
		s.logger.Errorf("failed to generate verification code: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Hash the code
	hashedCode, err := s.tokenMgr.HashToken(code)
	if err != nil {
		s.logger.Errorf("failed to hash verification code: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Save verification token
	if err := s.tokenRepo.SaveToken(ctx, user.ID, hashedCode, models.TwoFactorCode, s.config.AuthConfig.Tokens.TwoFactorTTL); err != nil {
		s.logger.Errorf("failed to save verification token: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Send verification SMS (assuming SMS sender is available)
	if s.config.Email.CustomSender != nil {
		if err := s.config.Email.CustomSender.SendTwoFactorEmail(ctx, *user, code); err != nil {
			s.logger.Errorf("failed to send verification SMS: %v", err)
			return types.NewSmsSendFailedError()
		}
	}

	return nil
}

// GetTwoFactorStatus gets the two-factor authentication status
func (s *TwoFactorService) GetTwoFactorStatus(ctx context.Context, userID string) (*dto.TwoFactorStatusResponse, *types.GoAuthError) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		s.logger.Errorf("user not found")
		return nil, types.NewUserNotFoundError()
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
		totpSecret, err := s.tokenRepo.GetTOTPSecretByUserID(ctx, userID)
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
func (s *TwoFactorService) TwoFactorLogin(ctx context.Context, req *dto.TwoFactorLoginRequest) (*dto.LoginResponse, *types.GoAuthError) {
	// First, verify email and password
	user, err := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		s.logger.Errorf("invalid credentials")
		return nil, types.NewInvalidCredentialsError()
	}

	// Check if user is active
	if user.Active != nil && !*user.Active {
		s.logger.Errorf("account is deactivated")
		return nil, types.NewAccountDeactivatedError()
	}

	// Verify password
	if err := s.tokenMgr.ValidatePassword(user.Password, req.Password); err != nil {
		s.logger.Errorf("invalid credentials")
		return nil, types.NewInvalidCredentialsError()
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		s.logger.Errorf("two-factor authentication is not enabled")
		return nil, types.NewTwoFactorNotEnabledError()
	}

	// Verify 2FA code
	verificationReq := &dto.TwoFactorVerificationRequest{
		Code:   req.Code,
		Method: req.Method,
	}
	if err := s.VerifyTwoFactor(ctx, user.ID, verificationReq); err != nil {
		s.logger.Errorf("two-factor verification failed: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Generate tokens
	accessToken, refreshToken, err := s.tokenMgr.GenerateTokens(user)
	if err != nil {
		s.logger.Errorf("failed to generate tokens: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Errorf("Failed to update last login: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	return &dto.LoginResponse{
		Message: "login successful",
		User:    s.mapUserToDTO(user),
		Tokens: dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}

// DisableTwoFactor disables two-factor authentication for a user
func (s *TwoFactorService) DisableTwoFactor(ctx context.Context, userID string, req *dto.DisableTwoFactorRequest) *types.GoAuthError {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		s.logger.Errorf("user not found")
		return types.NewUserNotFoundError()
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled == nil || !*user.TwoFactorEnabled {
		s.logger.Errorf("two-factor authentication is not enabled")
		return types.NewTwoFactorNotEnabledError()
	}

	// Verify password
	if err := s.tokenMgr.ValidatePassword(user.Password, req.Password); err != nil {
		s.logger.Errorf("invalid password")
		return types.NewInvalidCredentialsError()
	}

	// Disable 2FA
	twoFactorEnabled := false
	user.TwoFactorEnabled = &twoFactorEnabled
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Errorf("failed to disable two-factor authentication: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Clean up TOTP secrets
	if err := s.tokenRepo.DeleteTOTPSecret(ctx, &models.TotpSecret{UserID: userID}); err != nil {
		s.logger.Errorf("Failed to clean up TOTP secrets: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Clean up backup codes
	if err := s.tokenRepo.DeleteBackupCode(ctx, &models.BackupCode{UserID: userID}); err != nil {
		s.logger.Errorf("Failed to clean up backup codes: %v", err)
		return types.NewInternalError(err.Error())
	}

	// Revoke all 2FA tokens
	if err := s.tokenRepo.RevokeAllTokens(ctx, userID, models.TwoFactorCode); err != nil {
		s.logger.Errorf("Failed to revoke 2FA tokens: %v", err)
		return types.NewInternalError(err.Error())
	}

	return nil
}
