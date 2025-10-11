package types

type DriverType string

const (
	DriverTypeGorm  DriverType = "gorm"
	DriverTypeMongo DriverType = "mongo"
	DriverTypeSqlc  DriverType = "sqlc"
)

type DialectType string

const (
	DialectTypePostgres DialectType = "postgres"
	DialectTypeMysql    DialectType = "mysql"
	DialectTypeSqlite   DialectType = "sqlite"
)

type RepositoryName string

// Repository name constants for type-safe access
const (
	// Core module repositories
	CoreUserRepository                  RepositoryName = "core.user"
	CoreSessionRepository               RepositoryName = "core.session"
	CoreTokenRepository                 RepositoryName = "core.token"
	CoreVerificationTokenRepository     RepositoryName = "core.verification_token"
	CoreUserExtendedAttributeRepository RepositoryName = "core.user_attribute"

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
