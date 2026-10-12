package types

type ModuleName string

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
)

// CaptchaProvider represents a supported captcha provider.
type CaptchaProvider string

const (
	CaptchaProviderGoogle     CaptchaProvider = "google"
	CaptchaProviderCloudflare CaptchaProvider = "cloudflare"
)

// MagicLinkDeliveryMode controls what the magic-link email contains.
type MagicLinkDeliveryMode string

const (
	MagicLinkDeliveryModeLink MagicLinkDeliveryMode = "link" // link-only (classic magic link)
	MagicLinkDeliveryModeCode MagicLinkDeliveryMode = "code" // code-only (email OTP)
	MagicLinkDeliveryModeBoth MagicLinkDeliveryMode = "both" // both link and code (default)
)
