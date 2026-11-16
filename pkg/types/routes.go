package types

// RouteName is the stable name of a built-in route, such as "core.login".
type RouteName string

// Built-in route names. Use them in route patterns for middleware, rate-limit
// and captcha configuration; a pattern such as "core.*" matches a whole module.
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

	// Public JSON Web Key Set for verifying access / refresh tokens.
	// Only served when JWTAlgorithm is asymmetric (RS256 / ES256).
	RouteJWKS RouteName = "core.jwks"

	// Passkeys Routes
	RoutePasskeysRegisterBegin  RouteName = "passkeys.register_begin"
	RoutePasskeysRegisterFinish RouteName = "passkeys.register_finish"
	RoutePasskeysLoginBegin     RouteName = "passkeys.login_begin"
	RoutePasskeysLoginFinish    RouteName = "passkeys.login_finish"
	RoutePasskeysList           RouteName = "passkeys.list"
	RoutePasskeysDelete         RouteName = "passkeys.delete"
	RoutePasskeysRename         RouteName = "passkeys.rename"

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

	// SAML Routes
	RouteSAMLLogin     RouteName = "saml.login"
	RouteSAMLACS       RouteName = "saml.acs"
	RouteSAMLMetadata  RouteName = "saml.metadata"
	RouteSAMLProviders RouteName = "saml.providers"

	// IdP (OpenID Connect provider) Routes
	RouteIDPDiscovery          RouteName = "idp.discovery"
	RouteIDPJWKS               RouteName = "idp.jwks"
	RouteIDPAuthorize          RouteName = "idp.authorize"
	RouteIDPToken              RouteName = "idp.token"
	RouteIDPUserInfo           RouteName = "idp.userinfo"
	RouteIDPUserInfoPost       RouteName = "idp.userinfo.post"
	RouteIDPConsentGet         RouteName = "idp.consent.get"
	RouteIDPConsentApprove     RouteName = "idp.consent.approve"
	RouteIDPConsentDeny        RouteName = "idp.consent.deny"
	RouteIDPGrantsList         RouteName = "idp.grants.list"
	RouteIDPGrantsRevoke       RouteName = "idp.grants.revoke"
	RouteIDPAdminClientsList   RouteName = "idp.admin.clients.list"
	RouteIDPAdminClientsCreate RouteName = "idp.admin.clients.create"
	RouteIDPAdminClientsGet    RouteName = "idp.admin.clients.get"
	RouteIDPAdminClientsUpdate RouteName = "idp.admin.clients.update"
	RouteIDPAdminClientsDelete RouteName = "idp.admin.clients.delete"
	RouteIDPAdminClientsSecret RouteName = "idp.admin.clients.secret"

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
	RouteAdminListUsers        RouteName = "admin.users.list"
	RouteAdminGetUser          RouteName = "admin.users.get"
	RouteAdminCreateUser       RouteName = "admin.users.create"
	RouteAdminUpdateUser       RouteName = "admin.users.update"
	RouteAdminDeleteUser       RouteName = "admin.users.delete"
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

	// Organization Routes
	RouteOrgCreate RouteName = "org.create"
	RouteOrgMyOrgs RouteName = "org.my"
	RouteOrgGet    RouteName = "org.get"
	RouteOrgUpdate RouteName = "org.update"
	RouteOrgDelete RouteName = "org.delete"
	RouteOrgSwitch RouteName = "org.switch"

	// Organization Member Routes
	RouteOrgListMembers  RouteName = "org.members.list"
	RouteOrgGetMember    RouteName = "org.members.get"
	RouteOrgUpdateMember RouteName = "org.members.update"
	RouteOrgRemoveMember RouteName = "org.members.remove"

	// Organization Invitation Routes
	RouteOrgInvite            RouteName = "org.invite"
	RouteOrgListInvitations   RouteName = "org.invitations.list"
	RouteOrgCancelInvitation  RouteName = "org.invitations.cancel"
	RouteOrgAcceptInvitation  RouteName = "org.invitations.accept"
	RouteOrgDeclineInvitation RouteName = "org.invitations.decline"
	RouteOrgMyInvitations     RouteName = "org.my.invitations"

	// Invitation Routes (standalone)
	RouteInvitationSend    RouteName = "invitation.send"
	RouteInvitationList    RouteName = "invitation.list"
	RouteInvitationCancel  RouteName = "invitation.cancel"
	RouteInvitationAccept  RouteName = "invitation.accept"
	RouteInvitationDecline RouteName = "invitation.decline"
	RouteInvitationMy      RouteName = "invitation.my"

	// RBAC Routes (application-wide roles)
	RouteRBACPermissions     RouteName = "rbac.permissions.list"
	RouteRBACMyPermissions   RouteName = "rbac.me.permissions"
	RouteRBACListRoles       RouteName = "rbac.roles.list"
	RouteRBACCreateRole      RouteName = "rbac.roles.create"
	RouteRBACGetRole         RouteName = "rbac.roles.get"
	RouteRBACUpdateRole      RouteName = "rbac.roles.update"
	RouteRBACDeleteRole      RouteName = "rbac.roles.delete"
	RouteRBACGetUserRoles    RouteName = "rbac.users.roles.get"
	RouteRBACSetUserRoles    RouteName = "rbac.users.roles.set"
	RouteRBACListAssignments RouteName = "rbac.assignments.list"

	// RBAC Routes (organization roles)
	RouteRBACOrgListRoles       RouteName = "rbac.org.roles.list"
	RouteRBACOrgCreateRole      RouteName = "rbac.org.roles.create"
	RouteRBACOrgGetRole         RouteName = "rbac.org.roles.get"
	RouteRBACOrgUpdateRole      RouteName = "rbac.org.roles.update"
	RouteRBACOrgDeleteRole      RouteName = "rbac.org.roles.delete"
	RouteRBACOrgGetMemberRoles  RouteName = "rbac.org.members.roles.get"
	RouteRBACOrgSetMemberRoles  RouteName = "rbac.org.members.roles.set"
	RouteRBACOrgListAssignments RouteName = "rbac.org.assignments.list"

	// UI Routes (server-rendered pages)
	RouteUIAsset          RouteName = "ui.asset"
	RouteUIHome           RouteName = "ui.home"
	RouteUILoginPage      RouteName = "ui.login.page"
	RouteUILogin          RouteName = "ui.login"
	RouteUILoginTwoFactor RouteName = "ui.login.2fa"
	RouteUILogout         RouteName = "ui.logout"
	RouteUIAccount        RouteName = "ui.account"
)
