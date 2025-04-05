package types


type ServerType string

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

type DatabaseType string

const (
	PostgreSQL DatabaseType = "postgres"
	MySQL      DatabaseType = "mysql"
	MongoDB    DatabaseType = "mongodb"
	SQLite     DatabaseType = "sqlite"
)

type AuthProvider string

const (
	Google    AuthProvider = "google"
	GitHub    AuthProvider = "github"
	Facebook  AuthProvider = "facebook"
	Microsoft AuthProvider = "microsoft"
	Apple     AuthProvider = "apple"
	Discord  AuthProvider = "discord"
	Twitter   AuthProvider = "twitter"
	LinkedIn  AuthProvider = "linkedin"
	Spotify   AuthProvider = "spotify"
	Slack     AuthProvider = "slack"
	Custom    AuthProvider = "custom"
)
type RateLimiterStorageType string

const (
	RedisRateLimiter RateLimiterStorageType = "redis"
	MemoryRateLimiter RateLimiterStorageType = "memory"
	DatabaseRateLimiter RateLimiterStorageType = "database"
)