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
	RateLimiterModule  ModuleName = "ratelimiter"
	CaptchaModule      ModuleName = "captcha"
	ReportModule       ModuleName = "report"
	NotificationModule ModuleName = "notification"
)

// CaptchaProvider represents a supported captcha provider.
type CaptchaProvider string

const (
	CaptchaProviderGoogle     CaptchaProvider = "google"
	CaptchaProviderCloudflare CaptchaProvider = "cloudflare"
)
