package types

type ModuleName string

const (
	CoreModule         ModuleName = "core"
	TwoFactorModule    ModuleName = "twofactor"
	OAuthModule        ModuleName = "oauth"
	MagicLinkModule    ModuleName = "magiclink"
	AdminModule        ModuleName = "admin"
	CSRFModule         ModuleName = "csrf"
	RateLimiterModule  ModuleName = "ratelimiter"
	CaptchaModule      ModuleName = "captcha"
	ReportModule       ModuleName = "report"
	NotificationModule ModuleName = "notification"
)
