package auth_service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"gorm.io/gorm"
)

// Updated service method with proper error handling
func (s *AuthService) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, *types.GoAuthError) {
	// Get user by email
	user, err := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		s.logger.Errorf("failed to get user by email: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Check if user is active
	if user.Active != nil && !*user.Active {
		return nil, types.NewAccountDeactivatedError()
	}

	// Verify password
	if err := s.tokenMgr.ValidatePassword(user.Password, req.Password); err != nil {
		return nil, types.NewInvalidCredentialsError()
	}

	// Generate tokens
	accessToken, refreshToken, ierr := s.tokenMgr.GenerateTokens(user)
	if ierr != nil {
		s.logger.Errorf("failed to generate tokens: %v", ierr)
		return nil, types.NewInternalError(ierr.Error())
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Errorf("Failed to update last login: %v", err)
		// Don't fail login for this error
	}

	// Cache user
	if err := s.cache.Set(ctx, "user:"+user.ID, user, s.config.AuthConfig.JWT.AccessTokenTTL); err != nil {
		s.logger.Errorf("Failed to cache user: %v", err)
		// Don't fail login for this error
	}

	return &dto.LoginResponse{
		User: &dto.UserResponse{
			ID:            user.ID,
			Email:         user.Email,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			EmailVerified: user.EmailVerified != nil && *user.EmailVerified,
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// Logout handles user logout
func (s *AuthService) Logout(ctx context.Context, userID string, sessionID string) *types.GoAuthError {
	if s.config.AuthConfig.Methods.EnableMultiSession {
		session, err := s.sessionRepo.GetSessionBySessionID(ctx, sessionID)
		if err != nil {
			s.logger.Errorf("Failed to get session: %v", err)
			return types.NewInternalError(err.Error())
		}
		if session != nil {
			err = s.sessionRepo.DeleteSession(ctx, session)
			if err != nil {
				s.logger.Errorf("Failed to delete session: %v", err)
				return types.NewInternalError(err.Error())
			}
			return nil
		}
	}
	sessions, err := s.sessionRepo.GetSessionByUserID(ctx, userID)
	if err != nil {
		s.logger.Errorf("Failed to get session: %v", err)
		return types.NewInternalError(err.Error())
	}
	if len(sessions) < 0 {
		return nil
	}
	err = s.sessionRepo.DeleteAllUserSessions(ctx, userID)
	if err != nil {
		s.logger.Errorf("Failed to delete all user sessions: %v", err)
		return types.NewInternalError(err.Error())
	}
	return nil
}

// SendMagicLink handles magic link request
func (s *AuthService) SendMagicLink(ctx context.Context, req *dto.MagicLinkRequest) *types.GoAuthError {
	var user *models.User
	var magicToken string
	var hashedToken string
	var err error
	if req.Method == "phone" {
		user, err = s.userRepo.GetUserByPhoneNumber(ctx, req.Phone)
		if err != nil {
			s.logger.Errorf("failed to get user by phone number: %v", err)
			return types.NewInternalError(err.Error())
		}
		if user == nil {
			s.logger.Errorf("user not found")
			return types.NewUserNotFoundError()
		}
	} else if req.Method == "email" {
		user, err = s.userRepo.GetUserByEmail(ctx, req.Email)
		if err != nil {
			s.logger.Errorf("failed to get user by email: %v", err)
			return types.NewInternalError(err.Error())
		}
		if user == nil {
			s.logger.Errorf("user not found")
			return types.NewUserNotFoundError()
		}
	}
	if req.Method == "phone" {
		magicToken, err = s.tokenMgr.GenerateNumericOTP(6)
		if err != nil {
			s.logger.Errorf("failed to generate magic link token: %v", err)
			return types.NewInternalError(err.Error())
		}
		hashedToken, err = s.tokenMgr.HashToken(magicToken)
		if err != nil {
			s.logger.Errorf("failed to hash magic link token: %v", err)
			return types.NewInternalError(err.Error())
		}
	} else {
		// Generate magic link token
		magicToken, err = s.tokenMgr.GenerateRandomToken(32)
		if err != nil {
			s.logger.Errorf("failed to generate magic link token: %v", err)
			return types.NewInternalError(err.Error())
		}

		hashedToken, err = s.tokenMgr.HashToken(magicToken)
		if err != nil {
			s.logger.Errorf("failed to hash magic link token: %v", err)
			return types.NewInternalError(err.Error())
		}

	}

	existingToken, err := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, user.ID, models.MakicLinkToken)
	if err != nil {
		s.logger.Errorf("failed to get existing token: %v", err)
		return types.NewInternalError(err.Error())
	}
	if existingToken != nil {
		err = s.tokenRepo.RevokeToken(ctx, existingToken.ID)
		if err != nil {
			s.logger.Errorf("failed to revoke existing token: %v", err)
			return types.NewInternalError(err.Error())
		}
	}
	// Save magic link token (15 minutes expiry)
	expiry := s.config.AuthConfig.Tokens.MagicLinkTTL
	if err := s.tokenRepo.SaveToken(ctx, user.ID, hashedToken, models.MakicLinkToken, expiry); err != nil {
		s.logger.Errorf("failed to save magic link token: %v", err)
		return types.NewInternalError(err.Error())
	}

	s.logger.Debugf("Magic link sent to user %s", magicToken)

	if req.Method == "phone" {
		s.logger.Debugf("Magic link sent to user %s", magicToken)
		// Send magic link to user
		if err := s.config.SMS.CustomSender.SendMagicLoginOTPSMS(ctx, *user, magicToken); err != nil {
			s.logger.Errorf("failed to send magic link SMS: %v", err)
			return types.NewInternalError(err.Error())
		}
	} else {
		s.logger.Debugf("Magic link sent to user %s", magicToken)
		// Create magic link URL
		magicURL := fmt.Sprintf("%s/verify-magic-link?token=%s&email=%s", s.config.App.FrontendURL, magicToken, user.Email)

		// Send magic link email
		if s.config.Email.CustomSender != nil {
			if err := s.config.Email.CustomSender.SendMagicLinkEmail(ctx, *user, magicURL); err != nil {
				return types.NewInternalError(err.Error())
			}
		}
	}

	return nil
}

// VerifyMagicLink handles magic link verification
func (s *AuthService) VerifyMagicLink(ctx context.Context, req *dto.MagicLinkVerificationRequest) (*dto.LoginResponse, *types.GoAuthError) {
	var user *models.User
	var err error
	if req.Method == "phone" {
		user, err = s.userRepo.GetUserByPhoneNumber(ctx, req.Phone)
		if err != nil {
			s.logger.Errorf("failed to get user by phone number: %v", err)
			return nil, types.NewInternalError(err.Error())
		}
		if user == nil {
			s.logger.Errorf("user not found")
			return nil, types.NewUserNotFoundError()
		}
	} else if req.Method == "email" {
		user, err = s.userRepo.GetUserByEmail(ctx, req.Email)
		if err != nil {
			s.logger.Errorf("failed to get user by email: %v", err)
			return nil, types.NewInternalError(err.Error())
		}
		if user == nil {
			s.logger.Errorf("user not found")
			return nil, types.NewUserNotFoundError()
		}
	}

	token, err := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, user.ID, models.MakicLinkToken)
	if err != nil {
		s.logger.Errorf("failed to get token: %v", err)
		return nil, types.NewInternalError(err.Error())
	}
	if token == nil {
		s.logger.Errorf("token not found")
		return nil, types.NewTokenNotFoundError()
	}

	err = s.tokenMgr.ValidateHashedToken(token.TokenValue, req.Token)
	if err != nil {
		s.logger.Errorf("invalid token: %v", err)
		return nil, types.NewInvalidTokenError()
	}

	// Revoke the token

	err = s.tokenRepo.RevokeToken(ctx, token.ID)
	if err != nil {
		s.logger.Errorf("failed to revoke token: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	accessToken, refreshToken, err := s.tokenMgr.GenerateTokens(user)
	if err != nil {
		s.logger.Errorf("failed to generate tokens: %v", err)
		return nil, types.NewInternalError(err.Error())
	}
	hashedRefreshToken, err := s.tokenMgr.HashToken(refreshToken)
	if err != nil {
		s.logger.Errorf("failed to hash refresh token: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	session := &models.Session{
		UserID:       user.ID,
		RefreshToken: hashedRefreshToken,
		ExpiresAt:    time.Now().Add(s.config.AuthConfig.JWT.RefreshTokenTTL),
		IP:           req.Ip,
		UserAgent:    req.UserAgent,
		DeviceId:     &req.DeviceId,
		Location:     req.Location,
	}
	err = s.sessionRepo.CreateSession(ctx, session)
	if err != nil {
		s.logger.Errorf("failed to create session: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	response := dto.LoginResponse{
		// SessionId: session.ID,
		// Status:    http.StatusOK,
		// Message:   "Login successful",
		User: &dto.UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.AuthConfig.JWT.AccessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}

	return &response, nil
}

// ForgotPassword handles password reset request
func (s *AuthService) ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) *types.GoAuthError {
	// Get user by email
	var user *models.User

	var resetToken string
	var ierr error
	var hashedToken string
	if req.Method == "email" {
		user, ierr = s.userRepo.GetUserByEmail(ctx, req.Email)
		if ierr != nil {
			s.logger.Errorf("failed to get user by email: %v", ierr)
			return types.NewInternalError(ierr.Error())
		}
		if user == nil {
			s.logger.Errorf("user not found")
			return types.NewUserNotFoundError()
		}
	} else if req.Method == "phone" {
		user, ierr = s.userRepo.GetUserByPhoneNumber(ctx, req.Phone)
		if ierr != nil {
			s.logger.Errorf("failed to get user by phone number: %v", ierr)
			return types.NewInternalError(ierr.Error())
		}
		if user == nil {
			s.logger.Errorf("user not found")
			return types.NewUserNotFoundError()
		}
	}

	if req.Method == "email" {
		// Generate reset token
		var ierr error
		resetToken, ierr = s.tokenMgr.GenerateRandomToken(32)
		if ierr != nil {
			s.logger.Errorf("failed to generate reset token: %v", ierr)
			return types.NewInternalError(ierr.Error())
		}

		hashedToken, ierr = s.tokenMgr.HashToken(resetToken)
		if ierr != nil {
			s.logger.Errorf("failed to hash reset token: %v", ierr)
			return types.NewInternalError(ierr.Error())
		}

		// Create reset URL
		resetURL := fmt.Sprintf("%s/%s?token=%s", s.config.App.FrontendURL, s.config.App.ResetPasswordFrontendPath, resetToken)

		// Send reset email
		if s.config.Email.CustomSender != nil {
			s.logger.Infof("sending reset email to user %s %s", user.ID, resetToken)
			if err := s.config.Email.CustomSender.SendForgetPasswordEmail(ctx, *user, resetURL); err != nil {
				return types.NewInternalError(err.Error())
			}
		} else {
			s.logger.Errorf("no email sender configured")
		}
	} else if req.Method == "phone" {
		// Generate reset token
		resetToken, ierr := s.tokenMgr.GenerateNumericOTP(6)
		if ierr != nil {
			s.logger.Errorf("failed to generate reset token: %v", ierr.Error())
			return types.NewInternalError(ierr.Error())
		}
		hashedToken, ierr = s.tokenMgr.HashToken(resetToken)
		if ierr != nil {
			s.logger.Errorf("failed to hash reset token: %v", ierr.Error())
			return types.NewInternalError(ierr.Error())
		}

		// Send reset SMS
		if s.config.SMS.CustomSender != nil {
			s.logger.Infof("sending reset SMS to user %s %s", user.ID, resetToken)
			if err := s.config.SMS.CustomSender.SendForgetPasswordSMS(ctx, *user, resetToken); err != nil {
				return types.NewInternalError(err.Error())
			}
		} else {
			s.logger.Errorf("no SMS sender configured")
		}

	}
	// save token to db

	if err := s.tokenRepo.SaveToken(ctx, user.ID, hashedToken, models.ForgotPasswordToken, time.Hour); err != nil {
		s.logger.Errorf("failed to save token: %v", err.Error())
		return types.NewInternalError(err.Error())
	}

	return nil
}

// ResetPassword handles password reset
func (s *AuthService) ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) *types.GoAuthError {
	var user *models.User
	var ierr error
	if req.Method == "email" {
		user, ierr = s.userRepo.GetUserByEmail(ctx, req.Email)
		if ierr != nil {
			s.logger.Errorf("failed to get user by email: %v", ierr)
			return types.NewInternalError(ierr.Error())
		}
	} else if req.Method == "phone" {
		user, ierr = s.userRepo.GetUserByPhoneNumber(ctx, req.Phone)
		if ierr != nil {
			s.logger.Errorf("failed to get user by phone number: %v", ierr)
			return types.NewInternalError(ierr.Error())
		}
	}
	if user == nil {
		s.logger.Errorf("user not found")
		return types.NewUserNotFoundError()
	}

	// Verify token
	token, ierr := s.tokenRepo.GetActiveTokenByUserIdAndType(ctx, user.ID, models.ForgotPasswordToken)
	if ierr != nil {
		s.logger.Errorf("failed to get active token by user id and type: %v", ierr)
		return types.NewInternalError(ierr.Error())
	}
	if token == nil {
		s.logger.Errorf("token not found")
		return types.NewTokenNotFoundError()
	}

	// Verify token
	if ierr := s.tokenMgr.ValidateHashedToken(token.TokenValue, req.Token); ierr != nil {
		s.logger.Errorf("failed to validate token: %v", ierr)
		return types.NewInvalidTokenError()
	}

	// Update user password
	hashedPassword, ierr := s.tokenMgr.HashPassword(req.NewPassword)
	if ierr != nil {
		s.logger.Errorf("failed to hash password: %v", ierr)
		return types.NewInternalError(ierr.Error())
	}
	user.Password = hashedPassword

	// Revoke token
	if ierr := s.tokenRepo.RevokeToken(ctx, token.ID); ierr != nil {
		s.logger.Errorf("failed to revoke token: %v", ierr)
		return types.NewInternalError(ierr.Error())
	}

	// Update user
	if ierr := s.userRepo.UpdateUser(ctx, user); ierr != nil {
		s.logger.Errorf("failed to update user: %v", ierr)
		return types.NewInternalError(ierr.Error())
	}

	return nil
}

// RegisterWithInvitation handles invitation-based registration
func (s *AuthService) RegisterWithInvitation(ctx context.Context, req *dto.RegisterWithInvitationRequest) (*dto.RegisterResponse, *types.GoAuthError) {
	// Check if user already exists
	existingUser, err := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Errorf("failed to get user by email: %v", err)
		return nil, types.NewInternalError(err.Error())
	}
	if existingUser != nil {
		return nil, types.NewUserAlreadyExistsError()
	}

	// TODO: Validate invitation token
	// For now, we'll trust the invitation token from the frontend

	// Hash password
	hashedPassword, ierr := s.tokenMgr.HashPassword(req.Password)
	if ierr != nil {
		s.logger.Errorf("failed to hash password: %v", ierr)
		return nil, types.NewInternalError(ierr.Error())
	}

	// Create user
	emailVerified := !s.config.AuthConfig.Methods.EmailVerification.EnableOnSignup
	phoneVerified := !s.config.AuthConfig.Methods.PhoneVerification.EnableOnSignup
	twoFactorEnabled := false
	active := !(s.config.AuthConfig.Methods.EmailVerification.EnableOnSignup || s.config.AuthConfig.Methods.PhoneVerification.EnableOnSignup)
	isAdmin := false

	user := &models.User{
		Email:            req.Email,
		Password:         hashedPassword,
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		EmailVerified:    &emailVerified,
		PhoneVerified:    &phoneVerified,
		TwoFactorEnabled: &twoFactorEnabled,
		Active:           &active,
		IsAdmin:          &isAdmin,
		SignedUpVia:      "invitation",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Save user
	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		s.logger.Errorf("failed to create user: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Revoke invitation token
	s.tokenRepo.RevokeAllTokens(ctx, req.Email, models.InvitationToken)

	// Generate tokens
	accessToken, refreshToken, ierr := s.tokenMgr.GenerateTokens(user)
	if ierr != nil {
		s.logger.Errorf("failed to generate tokens: %v", ierr)
		return nil, types.NewInternalError(ierr.Error())
	}

	// Send welcome email
	if s.config.Email.CustomSender != nil && s.config.AuthConfig.Methods.EmailVerification.SendWelcomeEmail {
		if ierr := s.config.Email.CustomSender.SendWelcomeEmail(ctx, *user); ierr != nil {
			s.logger.Errorf("failed to send welcome email: %v", ierr)
			return nil, types.NewInternalError(ierr.Error())
		}
	}

	return &dto.RegisterResponse{
		Message: "registration successful",
		User:    s.mapUserToDTO(user),
		Tokens: &dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}

// Register handles user registration
func (s *AuthService) Register(ctx context.Context, req *dto.RegisterRequest) (resp *dto.RegisterResponse, err *types.GoAuthError) {

	resMessage := "registration successful"
	resp = &dto.RegisterResponse{}
	existingUser, ierr := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		err = types.NewUserAlreadyExistsError()
		resp.Status = http.StatusConflict
		return
	}
	if ierr != nil {
		s.logger.Errorf("failed to get user by email: %v", ierr)
		return nil, types.NewInternalError(ierr.Error())
	}

	// Hash password
	hashedPassword, ierr := s.tokenMgr.HashPassword(req.Password)
	if ierr != nil {
		s.logger.Errorf("Failed to hash password: %v", ierr)
		err = types.NewInternalError(ierr.Error())
		resp.Status = http.StatusInternalServerError
		return
	}

	// Create user
	emailVerified := !s.config.AuthConfig.Methods.EmailVerification.EnableOnSignup
	phoneVerified := !s.config.AuthConfig.Methods.PhoneVerification.EnableOnSignup
	twoFactorEnabled := false
	active := !(s.config.AuthConfig.Methods.EmailVerification.EnableOnSignup || s.config.AuthConfig.Methods.PhoneVerification.EnableOnSignup)
	isAdmin := false

	user := &models.User{
		Email:            req.Email,
		Password:         hashedPassword,
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		EmailVerified:    &emailVerified,
		PhoneVerified:    &phoneVerified,
		TwoFactorEnabled: &twoFactorEnabled,
		PhoneNumber:      &req.PhoneNumber,
		Active:           &active,
		IsAdmin:          &isAdmin,
		SignedUpVia:      "email",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Save user
	if ierr := s.userRepo.CreateUser(ctx, user); ierr != nil {
		s.logger.Errorf("Failed to create user: %v", ierr)
		err = types.NewInternalError(ierr.Error())
		resp.Status = http.StatusInternalServerError
		return
	}

	if s.config.AuthConfig.Methods.EmailVerification.EnableOnSignup && s.config.Email.CustomSender != nil {
		resMessage = "verification email sent"
		s.config.WorkerPool.Submit(func() {
			if s.config.Email.CustomSender != nil {
				ierr := s.config.Email.CustomSender.SendVerificationEmail(ctx, *user, s.config.App.FrontendURL)
				if ierr != nil {
					s.logger.Errorf("Failed to send verification email to %s: %v", user.Email, ierr)
				}
			}
		})
	}
	if s.config.AuthConfig.Methods.PhoneVerification.EnableOnSignup && s.config.SMS.CustomSender != nil {
		resMessage = "verification sms sent"
		s.config.WorkerPool.Submit(func() {
			if user.PhoneNumber == nil {
				s.logger.Errorf("Phone number is nil")
				return
			}
			if s.config.SMS.CustomSender != nil {
				ierr := s.config.SMS.CustomSender.SendVerificationSMS(ctx, *user, s.config.App.FrontendURL)
				if ierr != nil {
					s.logger.Errorf("Failed to send verification SMS to %s: %v", *user.PhoneNumber, ierr)
				}
			}
		})
	}

	// Send welcome email
	if s.config.Email.CustomSender != nil && s.config.AuthConfig.Methods.EmailVerification.SendWelcomeEmail {
		s.config.WorkerPool.Submit(func() {
			s.logger.Infof("Sending Welcome email to %s", user.Email)
			s.config.Email.CustomSender.SendWelcomeEmail(ctx, *user)
		})
	}

	if !s.config.AuthConfig.Methods.EmailVerification.EnableOnSignup && !s.config.AuthConfig.Methods.PhoneVerification.EnableOnSignup {
		accessToken, refreshToken, ierr := s.tokenMgr.GenerateTokens(user)
		if ierr != nil {
			s.logger.Errorf("Failed to generate tokens: %v", ierr)
			resp.Status = http.StatusInternalServerError
		}
		resp.Tokens = &dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.config.AuthConfig.JWT.AccessTokenTTL),
		}
	}
	resp.Message = resMessage
	resp.User = s.mapUserToDTO(user)
	resp.Status = http.StatusCreated

	return
}

// RefreshToken handles token refresh
func (s *AuthService) RefreshToken(ctx context.Context, sessionID string) (*dto.RefreshTokenResponse, *types.GoAuthError) {
	// Validate refresh token
	session, ierr := s.sessionRepo.GetSessionBySessionID(ctx, sessionID)
	if ierr != nil {
		return nil, types.NewInvalidSessionError()
	}

	userID := session.UserID
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, types.NewUserNotFoundError()
	}

	// Generate new tokens
	accessToken, refreshToken, err := s.tokenMgr.GenerateTokens(user)
	if err != nil {
		s.logger.Errorf("Failed to generate tokens: %v", err)
		return nil, types.NewInternalError(err.Error())
	}
	hashedRefreshToken, err := s.tokenMgr.HashToken(refreshToken)
	if err != nil {
		s.logger.Errorf("Failed to hash refresh token: %v", err)
		return nil, types.NewInternalError(err.Error())
	}
	session.RefreshToken = hashedRefreshToken
	// update session itself
	session.ExpiresAt = time.Now().Add(s.config.AuthConfig.JWT.AccessTokenTTL)
	err = s.sessionRepo.UpdateSession(ctx, session)
	if err != nil {
		s.logger.Errorf("Failed to update session: %v", err)
		return nil, types.NewInternalError(err.Error())
	}
	return &dto.RefreshTokenResponse{
		Message: "token refreshed successfully",
		Tokens: dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.config.AuthConfig.JWT.AccessTokenTTL),
		},
	}, nil
}
