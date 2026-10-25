package types

// ModuleName identifies a bundled module.
type ModuleName string

// Bundled module names.
const (
	CoreModule         ModuleName = "core"
	SessionModule      ModuleName = "session"
	StatelessModule    ModuleName = "stateless"
	TwoFactorModule    ModuleName = "twofactor"
	OAuthModule        ModuleName = "oauth"
	MagicLinkModule    ModuleName = "magiclink"
	AdminModule        ModuleName = "admin"
	AuditModule        ModuleName = "audit"
	CSRFModule         ModuleName = "csrf"
	CaptchaModule      ModuleName = "captcha"
	ReportModule       ModuleName = "report"
	NotificationModule ModuleName = "notification"
	OrganizationModule ModuleName = "organization"
	InvitationModule   ModuleName = "invitation"
	PasskeysModule     ModuleName = "passkeys"
	RateLimitModule    ModuleName = "ratelimit"
)

// CaptchaProvider represents a supported captcha provider.
type CaptchaProvider string

// Supported captcha providers.
const (
	CaptchaProviderGoogle     CaptchaProvider = "google"
	CaptchaProviderCloudflare CaptchaProvider = "cloudflare"
)

// MagicLinkDeliveryMode controls what the magic-link email contains.
type MagicLinkDeliveryMode string

// Magic-link delivery modes.
const (
	MagicLinkDeliveryModeLink MagicLinkDeliveryMode = "link" // link-only (classic magic link)
	MagicLinkDeliveryModeCode MagicLinkDeliveryMode = "code" // code-only (email OTP)
	MagicLinkDeliveryModeBoth MagicLinkDeliveryMode = "both" // both link and code (default)
)
