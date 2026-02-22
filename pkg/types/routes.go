package types

type RouteName string

const (
	// Core Routes
	RouteSignup         RouteName = "core.signup"
	RouteLogin          RouteName = "core.login"
	RouteLogout         RouteName = "core.logout"
	RouteMe             RouteName = "core.me"
	RouteProfile        RouteName = "core.profile"
	RouteUpdateProfile  RouteName = "core.update_profile"
	RouteChangePassword RouteName = "core.change_password"
	RouteChangeEmail    RouteName = "core.change_email"
	RouteChangePhone    RouteName = "core.change_phone"
	RouteRefreshToken   RouteName = "core.refresh_token"

	// availability routes
	RouteCheckAvailability RouteName = "core.check_availability"

	// Verification & Password Reset Routes
	RouteSendVerificationEmail   RouteName = "core.send_verification_email"
	RouteResendVerificationEmail RouteName = "core.resend_verification_email"
	RouteSendVerificationPhone   RouteName = "core.send_verification_phone"
	RouteResendVerificationPhone RouteName = "core.resend_verification_phone"
	RouteVerifyEmail             RouteName = "core.verify_email"
	RouteVerifyPhone             RouteName = "core.verify_phone"
	RouteForgotPassword          RouteName = "core.forgot_password"
	RouteResetPassword           RouteName = "core.reset_password"

	// OAuth Routes
	RouteOAuthLogin             RouteName = "oauth.login"
	RouteOAuthCallback          RouteName = "oauth.callback"
	RouteOAuthToken             RouteName = "oauth.token"
	RouteOAuthUserInfo          RouteName = "oauth.user_info"
	RouteOAuthUserLogout        RouteName = "oauth.user_logout"
	RouteOAuthUserProfile       RouteName = "oauth.user_profile"
	RouteOAuthUserUpdateProfile RouteName = "oauth.user_update_profile"
	RouteOAuthUserDeleteProfile RouteName = "oauth.user_delete_profile"

	// MagicLink Routes
	RouteMagicLinkSend       RouteName = "magiclink.send"
	RouteMagicLinkVerify     RouteName = "magiclink.verify"
	RouteMagicLinkVerifyCode RouteName = "magiclink.verify-code"
	RouteMagicLinkResend     RouteName = "magiclink.resend"

	// TwoFactor Routes
	RouteTwoFactorEnable    RouteName = "twofactor.enable"
	RouteTwoFactorDisable   RouteName = "twofactor.disable"
	RouteTwoFactorVerify    RouteName = "twofactor.verify"
	RouteTwoFactorResend    RouteName = "twofactor.resend"
	RouteTwoFactorAuth      RouteName = "twofactor.auth"
	RouteTwoFactorAuthSMS   RouteName = "twofactor.auth.sms"
	RouteTwoFactorAuthEmail RouteName = "twofactor.auth.email"

	// Admin Routes
	RouteAdminListUsers      RouteName = "admin.users.list"
	RouteAdminGetUser        RouteName = "admin.users.get"
	RouteAdminCreateUser     RouteName = "admin.users.create"
	RouteAdminUpdateUser     RouteName = "admin.users.update"
	RouteAdminDeleteUser     RouteName = "admin.users.delete"
	RouteAdminListAuditLogs    RouteName = "admin.audit.list"
	RouteAdminGetUserAudit     RouteName = "admin.audit.user"
	RouteAdminGetActionAudit   RouteName = "admin.audit.action"
	RouteAdminExportAudit      RouteName = "admin.audit.export"
	RouteAdminCleanupAuditLogs RouteName = "admin.audit.cleanup"

	// Audit Routes (user self-service)
	RouteAuditMyLogs     RouteName = "audit.my.logs"
	RouteAuditMyLogins   RouteName = "audit.my.logins"
	RouteAuditMyChanges  RouteName = "audit.my.changes"
	RouteAuditMySecurity RouteName = "audit.my.security"

	// CSRF Routes
	RouteCSRFToken RouteName = "csrf.get_token"
)
