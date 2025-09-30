package interfaces

import (
	"context"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
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
	Register(ctx context.Context, req *dto.RegisterRequest) (*dto.RegisterResponse, *types.GoAuthError)
	Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, *types.GoAuthError)
	Logout(ctx context.Context, userID string, sessionID string) *types.GoAuthError
	RefreshToken(ctx context.Context, refreshToken string) (*dto.RefreshTokenResponse, *types.GoAuthError)
	ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) *types.GoAuthError
	ResetPassword(ctx context.Context, req *dto.ResetPasswordRequest) *types.GoAuthError
	SendMagicLink(ctx context.Context, req *dto.MagicLinkRequest) *types.GoAuthError
	VerifyMagicLink(ctx context.Context, req *dto.MagicLinkVerificationRequest) (*dto.LoginResponse, *types.GoAuthError)
	RegisterWithInvitation(ctx context.Context, req *dto.RegisterWithInvitationRequest) (*dto.RegisterResponse, *types.GoAuthError)
}

type UserService interface {
	CreateUser(ctx context.Context, user *models.User) *types.GoAuthError
	GetUserByEmail(ctx context.Context, email string) (*dto.UserResponse, *types.GoAuthError)
	GetUserByPhoneNumber(ctx context.Context, phone string) (*dto.UserResponse, *types.GoAuthError)
	GetUserByID(ctx context.Context, userID string) (*dto.UserResponse, *types.GoAuthError)
	UpdateProfile(ctx context.Context, userID string, req *dto.UpdateProfileRequest) (*dto.UserResponse, *types.GoAuthError)
	DeactivateUser(ctx context.Context, userID string, req *dto.DeactivateUserRequest) *types.GoAuthError
	GetMe(ctx context.Context, userID string) (*dto.UserResponse, *types.GoAuthError)
	SendEmailVerification(ctx context.Context, email string) *types.GoAuthError
	VerifyEmail(ctx context.Context, req *dto.EmailVerificationRequest) *types.GoAuthError
	SendPhoneVerification(ctx context.Context, email string) *types.GoAuthError
	VerifyPhone(ctx context.Context, req *dto.PhoneVerificationRequest) *types.GoAuthError
	SendActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationRequest) *types.GoAuthError
	VerifyActionConfirmation(ctx context.Context, userID string, req *dto.ActionConfirmationVerificationRequest) *types.GoAuthError
}

// TwoFactorService handles two-factor authentication business logic
type TwoFactorService interface {
	EnableTwoFactor(ctx context.Context, userID string, req *dto.EnableTwoFactorRequest) (*dto.TwoFactorSetupResponse, *types.GoAuthError)
	VerifyTwoFactor(ctx context.Context, userID string, req *dto.TwoFactorVerificationRequest) *types.GoAuthError
	DisableTwoFactor(ctx context.Context, userID string, req *dto.DisableTwoFactorRequest) *types.GoAuthError
	VerifyTwoFactorSetup(ctx context.Context, userID string, req *dto.VerifyTwoFactorSetupRequest) *types.GoAuthError
	ResendTwoFactorCode(ctx context.Context, userID string, req *dto.ResendTwoFactorCodeRequest) *types.GoAuthError
	GetTwoFactorStatus(ctx context.Context, userID string) (*dto.TwoFactorStatusResponse, *types.GoAuthError)
	TwoFactorLogin(ctx context.Context, req *dto.TwoFactorLoginRequest) (*dto.LoginResponse, *types.GoAuthError)
}

// AdminService handles admin-specific business logic
type AdminService interface {
	ListUsers(ctx context.Context, req *dto.SearchRequest) (*dto.ListUsersResponse, *types.GoAuthError)
	GetUser(ctx context.Context, userID string) (*dto.AdminUserResponse, *types.GoAuthError)
	UpdateUser(ctx context.Context, userID string, req *dto.AdminUpdateUserRequest) (*dto.AdminUserResponse, *types.GoAuthError)
	DeleteUser(ctx context.Context, userID string) *types.GoAuthError
	ActivateUser(ctx context.Context, userID string) *types.GoAuthError
	BulkAction(ctx context.Context, req *dto.BulkActionRequest) (*dto.BulkActionResponse, *types.GoAuthError)
	GetSystemStats(ctx context.Context) (*dto.SystemStatsResponse, *types.GoAuthError)
	GetAuditLogs(ctx context.Context, req *dto.AuditLogsRequest) (*dto.AuditLogsResponse, *types.GoAuthError)
	GetSystemHealth(ctx context.Context) (*dto.SystemHealthResponse, *types.GoAuthError)
	ExportUsers(ctx context.Context, req *dto.ExportUsersRequest) (*dto.ExportUsersResponse, *types.GoAuthError)
	InviteUser(ctx context.Context, adminUserID string, req *dto.InviteUserRequest) (*dto.InviteUserResponse, *types.GoAuthError)
	ListInvitations(ctx context.Context, req *dto.ListInvitationsRequest) (*dto.ListInvitationsResponse, *types.GoAuthError)
	CancelInvitation(ctx context.Context, invitationID string) *types.GoAuthError
}

// CSRFService handles CSRF token business logic
type CSRFService interface {
	ValidateToken(ctx context.Context, userID string, token string) *types.GoAuthError
	GetCSRFToken(context.Context, string) (string, *types.GoAuthError)
}

// NotificationService handles email and SMS notifications
type NotificationService interface {
	SendVerificationEmail(ctx context.Context, user *models.User, redirectURL string) *types.GoAuthError
	SendWelcomeEmail(ctx context.Context, user *models.User) *types.GoAuthError
	SendForgetPasswordEmail(ctx context.Context, user *models.User, redirectURL string) *types.GoAuthError
	SendTwoFactorEmail(ctx context.Context, user *models.User, code string) *types.GoAuthError
	SendMagicLinkEmail(ctx context.Context, user *models.User, redirectURL string) *types.GoAuthError
	SendInvitationEmail(ctx context.Context, user *models.User, invitationURL string, invitedBy string) *types.GoAuthError
	SendVerificationSMS(ctx context.Context, user *models.User, code string) *types.GoAuthError
}

// OAuthService handles OAuth authentication business logic
type OAuthService interface {
	GenerateOAuthState(ctx context.Context, provider dto.OAuthProvider) (*dto.OAuthStateResponse, *types.GoAuthError)
	GetOAuthSignInURL(ctx context.Context, provider dto.OAuthProvider, state string) (string, *types.GoAuthError)
	HandleOAuthCallback(ctx context.Context, req *dto.OAuthCallbackRequest) (*dto.OAuthCallbackResponse, *types.GoAuthError)
	GetOAuthProviders(ctx context.Context) (*dto.OAuthProvidersResponse, *types.GoAuthError)
	LinkOAuthAccount(ctx context.Context, userID string, req *dto.OAuthLinkRequest) (*dto.OAuthLinkResponse, *types.GoAuthError)
	UnlinkOAuthAccount(ctx context.Context, userID string, req *dto.OAuthUnlinkRequest) (*dto.OAuthLinkResponse, *types.GoAuthError)
	GetUserOAuthAccounts(ctx context.Context, userID string) (*dto.OAuthUserAccountsResponse, *types.GoAuthError)
}
