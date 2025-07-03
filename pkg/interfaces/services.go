package interfaces

import (
	"context"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
)

// AuthService handles authentication business logic
type Service interface {
	AuthService
	UserService
	TwoFactorService
	AdminService
	CSRFService
	NotificationService
	OAuthService
}

type AuthService interface {
	Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, error)
	Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error)
	Logout(ctx context.Context, userID string) error
	RefreshToken(ctx context.Context, refreshToken string) (*dto.RefreshTokenResponse, error)
	ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) error
	ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) error
	SendMagicLink(ctx context.Context, req *dto.MagicLinkRequest) error
	VerifyMagicLink(ctx context.Context, req *dto.MagicLinkVerificationRequest) (*dto.LoginResponse, error)
	RegisterWithInvitation(ctx context.Context, req *dto.RegisterWithInvitationRequest) (*dto.RegisterResponse, error)
}

// UserService handles user management business logic
type UserService interface {
	GetUserByID(ctx context.Context, userID string) (*dto.UserResponse, error)
	UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserResponse, error)
	DeactivateUser(ctx context.Context, userID string, req *dto.DeactivateUserRequest) error
	SendEmailVerification(ctx context.Context, userID string) error
	VerifyEmail(ctx context.Context, req *dto.EmailVerificationRequest) error
	SendPhoneVerification(ctx context.Context, userID string) error
	VerifyPhone(ctx context.Context, req *dto.PhoneVerificationRequest) error
	SendActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationRequest) error
	VerifyActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationVerificationRequest) error
}

// TwoFactorService handles two-factor authentication business logic
type TwoFactorService interface {
	EnableTwoFactor(ctx context.Context, userID string, req *dto.EnableTwoFactorRequest) (*dto.TwoFactorSetupResponse, error)
	VerifyTwoFactor(ctx context.Context, userID string, req *dto.TwoFactorVerificationRequest) error
	DisableTwoFactor(ctx context.Context, userID string, req *dto.DisableTwoFactorRequest) error
	VerifyTwoFactorSetup(ctx context.Context, userID string, req *dto.VerifyTwoFactorSetupRequest) error
	ResendTwoFactorCode(ctx context.Context, userID string, req *dto.ResendTwoFactorCodeRequest) error
	GetTwoFactorStatus(ctx context.Context, userID string) (*dto.TwoFactorStatusResponse, error)
	TwoFactorLogin(ctx context.Context, req *dto.TwoFactorLoginRequest) (*dto.LoginResponse, error)
}

// AdminService handles admin-specific business logic
type AdminService interface {
	ListUsers(ctx context.Context, req *dto.ListUsersRequest) (*dto.ListUsersResponse, error)
	GetUser(ctx context.Context, userID string) (*dto.AdminUserResponse, error)
	UpdateUser(ctx context.Context, userID string, req *dto.AdminUpdateUserRequest) (*dto.AdminUserResponse, error)
	DeleteUser(ctx context.Context, userID string) error
	ActivateUser(ctx context.Context, userID string) error
	BulkAction(ctx context.Context, req *dto.BulkActionRequest) (*dto.BulkActionResponse, error)
	GetSystemStats(ctx context.Context) (*dto.SystemStatsResponse, error)
	GetAuditLogs(ctx context.Context, req *dto.AuditLogsRequest) (*dto.AuditLogsResponse, error)
	GetSystemHealth(ctx context.Context) (*dto.SystemHealthResponse, error)
	ExportUsers(ctx context.Context, req *dto.ExportUsersRequest) (*dto.ExportUsersResponse, error)
	InviteUser(ctx context.Context, adminUserID string, req *dto.InviteUserRequest) (*dto.InviteUserResponse, error)
	ListInvitations(ctx context.Context, req *dto.ListInvitationsRequest) (*dto.ListInvitationsResponse, error)
	CancelInvitation(ctx context.Context, invitationID string) error
}

// CSRFService handles CSRF token business logic
type CSRFService interface {
	ValidateToken(ctx context.Context, userID string, token string) error
	GetCSRFToken(ctx context.Context /*params*/) error
}

// NotificationService handles email and SMS notifications
type NotificationService interface {
	SendVerificationEmail(ctx context.Context, user *models.User, redirectURL string) error
	SendWelcomeEmail(ctx context.Context, user *models.User) error
	SendPasswordResetEmail(ctx context.Context, user *models.User, redirectURL string) error
	SendTwoFactorEmail(ctx context.Context, user *models.User, code string) error
	SendMagicLinkEmail(ctx context.Context, user *models.User, redirectURL string) error
	SendInvitationEmail(ctx context.Context, user *models.User, invitationURL string, invitedBy string) error
	SendVerificationSMS(ctx context.Context, user *models.User, code string) error
}

// OAuthService handles OAuth authentication business logic
type OAuthService interface {
	GenerateOAuthState(ctx context.Context, provider dto.OAuthProvider) (*dto.OAuthStateResponse, error)
	GetOAuthSignInURL(ctx context.Context, provider dto.OAuthProvider, state string) (string, error)
	HandleOAuthCallback(ctx context.Context, req *dto.OAuthCallbackRequest) (*dto.OAuthCallbackResponse, error)
	GetOAuthProviders(ctx context.Context) (*dto.OAuthProvidersResponse, error)
	LinkOAuthAccount(ctx context.Context, userID string, req *dto.OAuthLinkRequest) (*dto.OAuthLinkResponse, error)
	UnlinkOAuthAccount(ctx context.Context, userID string, req *dto.OAuthUnlinkRequest) (*dto.OAuthLinkResponse, error)
	GetUserOAuthAccounts(ctx context.Context, userID string) (*dto.OAuthUserAccountsResponse, error)
}
