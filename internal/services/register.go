package services

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
)

// Register handles user registration
func (s *AuthService) Register(ctx context.Context, req *dto.RegisterRequest) (resp *dto.RegisterResponse, err error) {

	resMessage := "registration successful"
	resp = &dto.RegisterResponse{}
	existingUser, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		err = errors.New("user with this email already exists")
		resp.Status = http.StatusConflict
		return
	}

	// Hash password
	hashedPassword, err := s.Auth.TokenManager.HashPassword(req.Password)
	if err != nil {
		s.Auth.Logger.Error("Failed to hash password: %v", err)
		err = errors.New("internal server error")
		resp.Status = http.StatusInternalServerError
		return
	}

	// Create user
	emailVerified := !s.Auth.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup
	phoneVerified := !s.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup
	twoFactorEnabled := false
	active := !(s.Auth.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup || s.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup)
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
	if err = s.Auth.Repository.GetUserRepository().CreateUser(ctx, user); err != nil {
		s.Auth.Logger.Errorf("Failed to create user: %v", err)
		err = errors.New("internal server error")
		resp.Status = http.StatusInternalServerError
		return
	}

	if s.Auth.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup && s.Auth.Config.Email.CustomSender != nil {
		resMessage = "verification email sent"
		s.Auth.WorkerPool.Submit(func() {
			err := s.sendEmailVerification(ctx, user)
			if err != nil {
				s.Auth.Logger.Errorf("Failed to send verification email to %s: %v", user.Email, err)
			}
		})
	}
	if s.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup && s.Auth.Config.SMS.CustomSender != nil {
		resMessage = "verification sms sent"
		s.Auth.WorkerPool.Submit(func() {
			if user.PhoneNumber == nil {
				s.Auth.Logger.Error("Phone number is nil")
				return
			}
			err := s.sendPhoneVerification(ctx, user)
			if err != nil {
				s.Auth.Logger.Errorf("Failed to send verification SMS to %s: %v", *user.PhoneNumber, err)
			}
		})
	}

	// Send welcome email
	if s.Auth.Config.Email.CustomSender != nil && s.Auth.Config.AuthConfig.Methods.EmailVerification.SendWelcomeEmail {
		s.Auth.WorkerPool.Submit(func() {
			s.Auth.Logger.Infof("Sending Welcome email to %s", user.Email)
			s.Auth.Config.Email.CustomSender.SendWelcomeEmail(ctx, *user)
		})
	}

	if !s.Auth.Config.AuthConfig.Methods.EmailVerification.EnableOnSignup && !s.Auth.Config.AuthConfig.Methods.PhoneVerification.EnableOnSignup {
		accessToken, refreshToken, err := s.Auth.TokenManager.GenerateTokens(user)
		if err != nil {
			s.Auth.Logger.Errorf("Failed to generate tokens: %v", err)
			resp.Status = http.StatusInternalServerError
		}
		resp.Tokens = &dto.TokenData{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresAt:    time.Now().Add(s.Auth.Config.AuthConfig.JWT.AccessTokenTTL),
		}
	}
	resp.Message = resMessage
	resp.User = s.mapUserToDTO(user)
	resp.Status = http.StatusCreated

	return
}
