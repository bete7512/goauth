package ratelimit

import (
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
)

// DefaultRules returns the rule set applied when no rules are configured.
// Credential checks and sends are limited per client IP and, where the
// request body carries an email, username or phone number, per identifier,
// so that neither one address nor one targeted account can be hammered.
// Authenticated routes are not limited by default.
func DefaultRules() []config.RateLimitRuleConfig {
	credentialChecks := []types.RouteName{
		types.RouteLogin,
		types.RouteTwoFactorAuth,
		"twofactor.auth.*",
		types.RouteTwoFactorVerify,
		types.RoutePasskeysLoginFinish,
		types.RouteMagicLinkVerify,
		types.RouteMagicLinkVerifyCode,
		types.RouteResetPassword,
		types.RouteVerifyPhone,
		types.RouteVerifyEmail,
		types.RouteInvitationAccept,
		types.RouteOrgAcceptInvitation,
		types.RouteUILogin,
		types.RouteUILoginTwoFactor,
		types.RouteUIAccountPassword,
		types.RouteUILoginCodeVerify,
		types.RouteUILoginPasskeyFinish,
		types.RouteIDPPageSignIn,
		types.RouteIDPPageTwoFactor,
	}
	sends := []types.RouteName{
		types.RouteForgotPassword,
		types.RouteSendVerificationEmail,
		types.RouteResendVerificationEmail,
		types.RouteSendVerificationPhone,
		types.RouteResendVerificationPhone,
		types.RouteMagicLinkSend,
		types.RouteMagicLinkResend,
		types.RouteTwoFactorResend,
		types.RouteInvitationSend,
		types.RouteUILoginCode,
	}
	return []config.RateLimitRuleConfig{
		{Name: "credential_ip", ApplyTo: credentialChecks, Key: types.RateLimitKeyIP, Limit: 30, Window: time.Minute},
		{Name: "credential_identifier", ApplyTo: credentialChecks, Key: types.RateLimitKeyIdentifier, Limit: 10, Window: 10 * time.Minute},
		{Name: "send_ip", ApplyTo: sends, Key: types.RateLimitKeyIP, Limit: 10, Window: time.Hour},
		{Name: "send_identifier", ApplyTo: sends, Key: types.RateLimitKeyIdentifier, Limit: 3, Window: time.Hour},
		{Name: "signup_ip", ApplyTo: []types.RouteName{types.RouteSignup}, Key: types.RateLimitKeyIP, Limit: 10, Window: time.Hour},
		{Name: "availability_ip", ApplyTo: []types.RouteName{types.RouteCheckAvailability}, Key: types.RateLimitKeyIP, Limit: 30, Window: time.Minute},
		{Name: "refresh_ip", ApplyTo: []types.RouteName{types.RouteRefreshToken}, Key: types.RateLimitKeyIP, Limit: 120, Window: time.Minute},
		// Every authorization request stores a pending record, so the
		// endpoint that starts a sign-in to another application is limited.
		{Name: "idp_authorize_ip", ApplyTo: []types.RouteName{types.RouteIDPAuthorize}, Key: types.RateLimitKeyIP, Limit: 60, Window: time.Minute},
		// The identity provider's token and UserInfo endpoints are called by
		// applications' servers, many users behind one address, so the
		// budget is larger.
		{Name: "idp_token_ip", ApplyTo: []types.RouteName{types.RouteIDPToken, types.RouteIDPUserInfo, types.RouteIDPUserInfoPost}, Key: types.RateLimitKeyIP, Limit: 300, Window: time.Minute},
		{Name: "federation_ip", ApplyTo: []types.RouteName{types.RouteOAuthLogin, types.RouteOAuthCallback, types.RouteSAMLLogin, types.RouteSAMLACS, types.RoutePasskeysLoginBegin, types.RoutePasskeysRegisterBegin, types.RouteUILoginPasskeyBegin}, Key: types.RateLimitKeyIP, Limit: 60, Window: time.Minute},
	}
}
