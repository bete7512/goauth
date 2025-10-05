package config

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

type RepositoryName string

// Repository name constants for type-safe access
const (
	// Core module repositories
	CoreUserRepository              RepositoryName = "core.user"
	CoreSessionRepository           RepositoryName = "core.session"
	CoreTokenRepository             RepositoryName = "core.token"
	CoreVerificationTokenRepository RepositoryName = "core.verification_token"

	// Admin module repositories
	AdminAuditLogRepository RepositoryName = "admin.auditlog"

	// MagicLink module repositories
	MagicLinkRepository RepositoryName = "magiclink.token"

	// TwoFactor module repositories
	TwoFactorRepository RepositoryName = "twofactor.secret"

	// OAuth module repositories
	OAuthProviderRepository RepositoryName = "oauth.provider"
	OAuthTokenRepository    RepositoryName = "oauth.token"
)
