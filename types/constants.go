package types


const (
	RecaptchaAPIURL  = "https://www.google.com/recaptcha/api/siteverify"
	CloudflareAPIURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

const (
	RecaptchaGoogle     RecaptchaProvider = "google"
	RecaptchaCloudflare RecaptchaProvider = "cloudflare"
)

const (
	GinServer        ServerType = "gin"
	HttpServer       ServerType = "http"
	GorrilaMuxServer ServerType = "gorrila-mux"
	ChiServer        ServerType = "chi"
	FiberServer      ServerType = "fiber"
)
const (
	RouteRegister                = "register"
	RouteLogin                   = "login"
	RouteLogout                  = "logout"
	RouteRefreshToken            = "refresh-token"
	RouteForgotPassword          = "forgot-password"
	RouteResetPassword           = "reset-password"
	RouteUpdateProfile           = "update-profile"
	RouteDeactivateUser          = "deactivate-user"
	RouteGetMe                   = "me"
	RouteEnableTwoFactor         = "enable-two-factor"
	RouteVerifyTwoFactor         = "verify-two-factor"
	RouteDisableTwoFactor        = "disable-two-factor"
	RouteVerifyEmail             = "verify-email"
	RouteResendVerificationEmail = "resend-verification-email"
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
