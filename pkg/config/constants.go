package config

const (
	RecaptchaAPIURL  = "https://www.google.com/recaptcha/api/siteverify"
	CloudflareAPIURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

const (
	RecaptchaGoogle     RecaptchaProvider = "google"
	RecaptchaCloudflare RecaptchaProvider = "cloudflare"
)


const (
	RouteRegister                 = "register"
	RouteLogin                    = "login"
	RouteLogout                   = "logout"
	RouteRefreshToken             = "refresh-token"
	RouteForgotPassword           = "forgot-password"
	RouteResetPassword            = "reset-password"
	RouteUpdateProfile            = "update-profile"
	RouteDeactivateUser           = "deactivate-user"
	RouteGetMe                    = "me"
	RouteEnableTwoFactor          = "enable-two-factor"
	RouteVerifyTwoFactor          = "verify-two-factor"
	RouteDisableTwoFactor         = "disable-two-factor"
	RouteSendMagicLink            = "send-magic-link"
	RouteVerifyMagicLink          = "verify-magic-link"
	RouteSendEmailVerification    = "send-email-verification"
	RouteSendPhoneVerification    = "send-phone-verification"
	RouteVerifyEmail              = "verify-email"
	RouteVerifyPhone              = "verify-phone"
	RouteSendActionConfirmation   = "send-action-confirmation"
	RouteVerifyActionConfirmation = "verify-action-confirmation"
)

const (
	PostgreSQL DatabaseType = "postgres"
	MySQL      DatabaseType = "mysql"
	MongoDB    DatabaseType = "mongodb"
	SQLite     DatabaseType = "sqlite"
)

const (
	Google    AuthProvider = "google"
	GitHub    AuthProvider = "github"
	Facebook  AuthProvider = "facebook"
	Microsoft AuthProvider = "microsoft"
	Apple     AuthProvider = "apple"
	Discord   AuthProvider = "discord"
	Twitter   AuthProvider = "twitter"
	LinkedIn  AuthProvider = "linkedin"
	Spotify   AuthProvider = "spotify"
	Slack     AuthProvider = "slack"
	Custom    AuthProvider = "custom"
)
const (
	RedisRateLimiter    RateLimiterStorageType = "redis"
	MemoryRateLimiter   RateLimiterStorageType = "memory"
	DatabaseRateLimiter RateLimiterStorageType = "database"
)

const (
	ResponseDataKey contextKey = "response_data"
	RequestDataKey  contextKey = "request_data"
	UserIDKey       contextKey = "user_id"
	IsAdminKey      contextKey = "is_admin"
)

const (
	AuthenticationTypeCookie  AuthenticationType = "cookie"
	AuthenticationTypeBearer  AuthenticationType = "bearer"
	AuthenticationTypeSession AuthenticationType = "session"
)

const (
	SES      SenderType = "SES"
	SendGrid SenderType = "SendGrid"
)
