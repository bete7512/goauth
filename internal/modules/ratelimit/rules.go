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
	}
	return []config.RateLimitRuleConfig{
		{Name: "credential_ip", ApplyTo: credentialChecks, Key: types.RateLimitKeyIP, Limit: 30, Window: time.Minute},
		{Name: "credential_identifier", ApplyTo: credentialChecks, Key: types.RateLimitKeyIdentifier, Limit: 10, Window: 10 * time.Minute},
		{Name: "send_ip", ApplyTo: sends, Key: types.RateLimitKeyIP, Limit: 10, Window: time.Hour},
		{Name: "send_identifier", ApplyTo: sends, Key: types.RateLimitKeyIdentifier, Limit: 3, Window: time.Hour},
		{Name: "signup_ip", ApplyTo: []types.RouteName{types.RouteSignup}, Key: types.RateLimitKeyIP, Limit: 10, Window: time.Hour},
		{Name: "availability_ip", ApplyTo: []types.RouteName{types.RouteCheckAvailability}, Key: types.RateLimitKeyIP, Limit: 30, Window: time.Minute},
		{Name: "refresh_ip", ApplyTo: []types.RouteName{types.RouteRefreshToken}, Key: types.RateLimitKeyIP, Limit: 120, Window: time.Minute},
		{Name: "federation_ip", ApplyTo: []types.RouteName{types.RouteOAuthLogin, types.RouteOAuthCallback, types.RoutePasskeysLoginBegin, types.RoutePasskeysRegisterBegin}, Key: types.RateLimitKeyIP, Limit: 60, Window: time.Minute},
	}
}
