---
id: models
title: Models Reference
sidebar_label: Models
sidebar_position: 4
---

# Models Reference

All GoAuth data models live in the `pkg/models` package. Each model maps to a database table (via GORM tags) and has an associated repository interface for data access.

Built-in flows generally generate UUIDv7 entity IDs; external identity and WebAuthn credential identifiers retain their own formats. GoAuth does not use soft deletes.

---

## Sentinel Error

```go
var ErrNotFound = errors.New("record not found")
var ErrConflict = errors.New("security state conflict")
```

Repository methods return `models.ErrNotFound` when the requested record does not exist. Check for it with:

```go
if errors.Is(err, models.ErrNotFound) {
    // record does not exist
}
```

This is a standard `error`, not a `*types.GoAuthError`. It is used at the storage layer, while `*types.GoAuthError` is used at the service/handler layer.

---

`models.ErrConflict` reports a failed conditional mutation, such as replaying a consumed token or trying to advance a passkey counter with a stale value. See [Storage contracts](../storage.md).

## Core Models

### User

Table: `users`

```go
type User struct {
	ID                  string `json:"id" gorm:"primaryKey"`
	Name                string `json:"name"`
	FirstName           string `json:"first_name"`
	LastName            string `json:"last_name"`
	Email               string `json:"email" gorm:"uniqueIndex;not null"`
	Username            string `json:"username" gorm:"uniqueIndex"`
	PasswordHash        string `json:"-" gorm:"column:password;not null"`
	Avatar              string `json:"avatar"`
	PhoneNumber         string `json:"phone_number"`
	Active              bool   `json:"active" gorm:"default:true"`
	EmailVerified       bool   `json:"email_verified" gorm:"default:false"`
	PhoneNumberVerified bool   `json:"phone_number_verified" gorm:"default:false"`
	IsSuperAdmin        bool   `json:"is_super_admin" gorm:"default:false;not null;index"`
	// TokenVersion is used for stateless token revocation
	// Incrementing this value invalidates all existing tokens for the user
	TokenVersion        int        `json:"-" gorm:"default:0;not null"`
	FailedLoginAttempts int        `json:"-" gorm:"default:0;not null"`
	LockedUntil         *time.Time `json:"-" gorm:"index"`
	CreatedAt           time.Time  `json:"created_at"`
	LastLoginAt         *time.Time `json:"last_login_at"`
	UpdatedAt           *time.Time `json:"updated_at"`
}
```

**Hidden fields** (never serialized to JSON):

| Field | Purpose |
|---|---|
| `PasswordHash` | Bcrypt-hashed password. Stored in the `password` DB column. |
| `TokenVersion` | Incremented to invalidate existing credentials checked by the built-in strategies for this user. |
| `FailedLoginAttempts` | Counter for account lockout after repeated failures. |
| `LockedUntil` | Timestamp until which the account is locked. Nil means not locked. |

#### UserRepository

```go
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByPhoneNumber(ctx context.Context, phoneNumber string) (*User, error)
	FindByEmailOrUsername(ctx context.Context, emailOrUsername string) (*User, error)
	List(ctx context.Context, opts UserListOpts) ([]*User, int64, error)
	FindByID(ctx context.Context, id string) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
	IsAvailable(ctx context.Context, field, value string) (bool, error)
}
```

---

### Token

Table: `tokens`

Used for all verification and state tokens: email verification, phone verification, password reset, two-factor codes, magic links, and OAuth state parameters.

```go
type Token struct {
	// Data stores typed, purpose-specific continuation state; never serialize it.
	Data        string     `json:"-" gorm:"type:text"`
	ID          string     `json:"id" gorm:"primaryKey"`
	UserID      string     `json:"user_id" gorm:"not null;index"`
	Type        string     `json:"type" gorm:"not null;index"`
	Token       string     `json:"token" gorm:"uniqueIndex;not null"`
	Code        string     `json:"code,omitempty" gorm:"index"`
	Email       string     `json:"email,omitempty" gorm:"index"`
	PhoneNumber string     `json:"phone_number,omitempty" gorm:"index"`
	ExpiresAt   time.Time  `json:"expires_at" gorm:"not null;index"`
	Used        bool       `json:"used" gorm:"default:false"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	Attempts    int        `json:"attempts" gorm:"not null;default:0"`
	CreatedAt   time.Time  `json:"created_at"`
}
```

**Token type constants:**

| Constant | Value | Used By |
|---|---|---|
| `TokenTypeEmailVerification` | `"email_verification"` | Core module -- email verification flow |
| `TokenTypePhoneVerification` | `"phone_verification"` | Core module -- phone verification flow |
| `TokenTypePasswordReset` | `"password_reset"` | Core module -- password reset flow |
| `TokenTypeTwoFactorCode` | `"two_factor_code"` | Two-factor module -- code-based 2FA |
| `TokenTypeMagicLink` | `"magic_link"` | Magic link module -- passwordless auth |
| `TokenTypeOAuthState` | `"oauth_state"` | OAuth module -- CSRF state parameter |

#### TokenRepository

```go
type TokenRepository interface {
	Create(ctx context.Context, token *Token) error
	FindByToken(ctx context.Context, token string) (*Token, error)
	FindByUserID(ctx context.Context, userID string) ([]*Token, error)
	FindByCode(ctx context.Context, code, tokenType string) (*Token, error)
	FindByEmailAndType(ctx context.Context, email, tokenType string) (*Token, error)
	FindByPhoneAndType(ctx context.Context, phone, tokenType string) (*Token, error)
	IncrementAttempts(ctx context.Context, id string) (int, error)
	// MarkAsUsed atomically consumes an unused, unexpired token. Exactly one
	// concurrent caller succeeds; all others receive ErrConflict.
	MarkAsUsed(ctx context.Context, id string) error
	Delete(ctx context.Context, token string) error
	DeleteByIDAndType(ctx context.Context, id string, tokenType string) error
	DeleteByUserID(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) (int64, error)
}
```

---

## Session Module Models

### Session

Table: `sessions`

Represents an active user session. Only created when the session module is registered (mutually exclusive with the stateless module).

```go
type Session struct {
	AuthData              string    `json:"-" gorm:"type:text"`
	ID                    string    `json:"id" gorm:"primaryKey"`
	UserID                string    `json:"user_id" gorm:"not null;index"`
	RefreshToken          string    `json:"refresh_token" gorm:"uniqueIndex;not null"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at" gorm:"not null;index"`
	ExpiresAt             time.Time `json:"expires_at" gorm:"not null;index"`
	UserAgent             string    `json:"user_agent"`
	IPAddress             string    `json:"ip_address"`
	ReplacedBy            string    `json:"replaced_by"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}
```

The `ReplacedBy` field tracks refresh token rotation: when a session is refreshed, the old session record stores the ID of the new session that replaced it.

#### SessionRepository

```go
type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	FindByID(ctx context.Context, id string) (*Session, error)
	FindByToken(ctx context.Context, token string) (*Session, error)
	FindByUserID(ctx context.Context, userID string, opts SessionListOpts) ([]*Session, int64, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, id string) error
	DeleteByToken(ctx context.Context, token string) error
	DeleteByUserID(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) (int64, error)
}
```

---

## Stateless Module Models

### Blacklist

Table: *(not yet defined)*

Placeholder model for the stateless module's token blacklist. Currently an empty struct and interface, reserved for future blacklist-based token revocation.

```go
type Blacklist struct{}

type BlacklistRepository interface{}
```

---

## OAuth Module Models

### Account

Table: `accounts`

Represents an OAuth/OIDC provider link for a user. A single user can have multiple accounts (e.g. Google + GitHub). This model is only created when the OAuth module is used.

```go
type Account struct {
	RealmID           string     `json:"realm_id" gorm:"not null;default:default"`
	Issuer            string     `json:"issuer,omitempty"`
	ID                string     `json:"id" gorm:"primaryKey"`
	UserID            string     `json:"user_id" gorm:"not null;index"`
	Provider          string     `json:"provider" gorm:"not null;index"`      // configured connection ID
	ProviderAccountID string     `json:"provider_account_id" gorm:"not null"` // Provider's unique user ID
	Type              string     `json:"type" gorm:"not null"`                // oauth, oidc
	AccessToken       string     `json:"-" gorm:"type:text"`                  // Encrypted provider access token
	RefreshToken      string     `json:"-" gorm:"type:text"`                  // Encrypted provider refresh token
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`                // Provider token expiry
	TokenType         string     `json:"token_type,omitempty"`                // Usually "Bearer"
	Scope             string     `json:"scope,omitempty"`                     // Granted scopes
	IDToken           string     `json:"-" gorm:"type:text"`                  // OIDC ID token (for reference)
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}
```

**Account type constants:**

| Constant | Value | Description |
|---|---|---|
| `AccountTypeOAuth` | `"oauth"` | Standard OAuth 2.0 provider |
| `AccountTypeOIDC` | `"oidc"` | OpenID Connect provider |
| `AccountTypeCredentials` | `"credentials"` | Password-based authentication |

**Hidden fields** (never serialized to JSON):

| Field | Purpose |
|---|---|
| `AccessToken` | Provider access token, encrypted at rest (AES-256-GCM). |
| `RefreshToken` | Provider refresh token, encrypted at rest. |
| `IDToken` | OIDC ID token, stored for reference. |

#### AccountRepository

```go
type AccountRepository interface {
	// Create creates a new account
	Create(ctx context.Context, account *Account) error

	// FindByID finds an account by its ID
	FindByID(ctx context.Context, id string) (*Account, error)

	// FindByProviderAndAccountID finds an account by provider and provider's user ID
	// This is the primary lookup method for OAuth login
	FindByProviderAndAccountID(ctx context.Context, provider, providerAccountID string) (*Account, error)

	// FindByUserID finds all accounts for a user
	FindByUserID(ctx context.Context, userID string) ([]*Account, error)

	// FindByUserIDAndProvider finds a specific provider account for a user
	FindByUserIDAndProvider(ctx context.Context, userID, provider string) (*Account, error)

	// Update updates an account (e.g., refresh tokens)
	Update(ctx context.Context, account *Account) error

	// Delete deletes an account by ID
	Delete(ctx context.Context, id string) error

	// DeleteByUserIDAndProvider deletes a user's account for a specific provider
	DeleteByUserIDAndProvider(ctx context.Context, userID, provider string) error

	// CountByUserID counts the number of accounts for a user
	CountByUserID(ctx context.Context, userID string) (int64, error)
}
```

---

## Two-Factor Module Models

### TwoFactor

Table: `two_factors`

Stores the 2FA configuration for a user. Each user has at most one `TwoFactor` record.

```go
type TwoFactor struct {
	ID             string     `json:"id" gorm:"primaryKey"`
	UserID         string     `json:"user_id" gorm:"uniqueIndex;not null"`
	Secret         string     `json:"-" gorm:"not null"` // TOTP secret (encrypted in storage)
	Enabled        bool       `json:"enabled" gorm:"default:false"`
	Verified       bool       `json:"verified" gorm:"default:false"`
	Method         string     `json:"method" gorm:"default:'totp'"` // totp, sms, email
	FailedAttempts int        `json:"failed_attempts" gorm:"default:0"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}
```

**Hidden fields:**

| Field | Purpose |
|---|---|
| `Secret` | TOTP secret key, encrypted in storage (AES-256-GCM). |

The `Method` field indicates the 2FA method: `"totp"`, `"sms"`, or `"email"`.

The `Verified` field is `false` until the user successfully confirms their first TOTP code, proving they have set up their authenticator app correctly.

#### TwoFactorRepository

```go
type TwoFactorRepository interface {
	Create(ctx context.Context, tf *TwoFactor) error
	GetByUserID(ctx context.Context, userID string) (*TwoFactor, error)
	Update(ctx context.Context, tf *TwoFactor) error
	Delete(ctx context.Context, userID string) error
}
```

---

### BackupCode

Table: `backup_codes`

Recovery codes for 2FA. Users receive a set of backup codes when enabling 2FA; each code can be used exactly once.

```go
type BackupCode struct {
	ID        string     `json:"id" gorm:"primaryKey"`
	UserID    string     `json:"user_id" gorm:"index;not null"`
	Code      string     `json:"-" gorm:"not null"` // Hashed with bcrypt
	Used      bool       `json:"used" gorm:"default:false"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
```

**Hidden fields:**

| Field | Purpose |
|---|---|
| `Code` | The backup code, hashed with bcrypt. Never exposed in API responses. |

#### BackupCodeRepository

```go
type BackupCodeRepository interface {
	CreateBatch(ctx context.Context, codes []*BackupCode) error
	GetByUserID(ctx context.Context, userID string) ([]*BackupCode, error)
	GetUnusedByUserID(ctx context.Context, userID string) ([]*BackupCode, error)
	// MarkUsed atomically consumes an unused code; replay returns ErrConflict.
	MarkUsed(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
}
```

---

## Audit Module Models

### AuditLog

Table: `audit_logs`

Cross-cutting concern used by all modules (core, admin, audit, organization) to track system actions.

```go
type AuditLog struct {
	ID         string    `json:"id" gorm:"primaryKey"`
	Action     string    `json:"action" gorm:"not null;index"`         // e.g., "auth.login", "admin.user.delete"
	ActorID    string    `json:"actor_id" gorm:"not null;index"`       // User who performed the action
	ActorType  string    `json:"actor_type" gorm:"default:'user'"`     // "user", "admin", "system"
	TargetID   *string   `json:"target_id,omitempty" gorm:"index"`     // Resource affected (optional)
	TargetType *string   `json:"target_type,omitempty"`                // "user", "organization", "resource"
	Details    string    `json:"details" gorm:"type:text"`             // Human-readable description
	Metadata   string    `json:"metadata,omitempty" gorm:"type:jsonb"` // JSON: {ip, user_agent, device, location}
	Severity   string    `json:"severity" gorm:"default:'info';index"` // "info", "warning", "critical"
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at" gorm:"index"`
}
```

**Field details:**

| Field | Description | Example values |
|---|---|---|
| `Action` | Dot-notation action identifier | `"auth.login"`, `"admin.user.delete"` |
| `ActorID` | UUID of the user who performed the action | |
| `ActorType` | Type of actor | `"user"`, `"admin"`, `"system"` |
| `TargetID` | UUID of the affected resource (optional) | |
| `TargetType` | Type of the affected resource | `"user"`, `"organization"`, `"resource"` |
| `Details` | Human-readable description | |
| `Metadata` | JSON blob with contextual data | `{"ip": "...", "user_agent": "...", "device": "..."}` |
| `Severity` | Log severity level | `"info"`, `"warning"`, `"critical"` |

#### AuditLogRepository

```go
type AuditLogRepository interface {
	// Create creates a new audit log entry
	Create(ctx context.Context, log *AuditLog) error

	// FindByActorID finds audit logs by the user who performed actions
	FindByActorID(ctx context.Context, actorID string, opts AuditLogListOpts) ([]*AuditLog, int64, error)

	// FindByTargetID finds audit logs where the user was the target of actions
	FindByTargetID(ctx context.Context, targetID string, opts AuditLogListOpts) ([]*AuditLog, int64, error)

	// FindByAction finds audit logs by action type
	FindByAction(ctx context.Context, action string, opts AuditLogListOpts) ([]*AuditLog, int64, error)

	// FindBySeverity finds audit logs by severity level
	FindBySeverity(ctx context.Context, severity string, opts AuditLogListOpts) ([]*AuditLog, int64, error)

	// FindByOrganizationID finds audit logs for an organization (future)
	FindByOrganizationID(ctx context.Context, orgID string, opts AuditLogListOpts) ([]*AuditLog, int64, error)

	// List retrieves all audit logs with pagination
	List(ctx context.Context, opts AuditLogListOpts) ([]*AuditLog, int64, error)

	// DeleteOlderThan deletes audit logs older than the specified time
	DeleteOlderThan(ctx context.Context, before time.Time) error

	// DeleteByActionOlderThan deletes audit logs for specific action older than specified time
	DeleteByActionOlderThan(ctx context.Context, action string, before time.Time) error
}
```

---

## Organization Module Models

### Organization

Table: `organizations` (inferred from convention; no explicit `TableName()` override)

```go
type Organization struct {
	ID        string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	Name      string     `json:"name" gorm:"type:varchar(255);not null"`
	Slug      string     `json:"slug" gorm:"type:varchar(255);uniqueIndex;not null"`
	OwnerID   string     `json:"owner_id" gorm:"type:varchar(36);not null"`
	LogoURL   string     `json:"logo_url,omitempty" gorm:"type:varchar(512)"`
	Metadata  string     `json:"metadata,omitempty" gorm:"type:text"`
	Active    bool       `json:"active" gorm:"default:true"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}
```

#### OrganizationRepository

```go
type OrganizationRepository interface {
	Create(ctx context.Context, org *Organization) error
	FindByID(ctx context.Context, id string) (*Organization, error)
	FindBySlug(ctx context.Context, slug string) (*Organization, error)
	FindByOwnerID(ctx context.Context, ownerID string) ([]*Organization, error)
	List(ctx context.Context, opts OrganizationListOpts) ([]*Organization, int64, error)
	Update(ctx context.Context, org *Organization) error
	Delete(ctx context.Context, id string) error
	IsSlugAvailable(ctx context.Context, slug string) (bool, error)
}
```

---

### OrganizationMember

Table: `organization_members` (inferred from convention)

Represents a user's membership in an organization. The composite unique index on `(org_id, user_id)` prevents duplicate memberships.

```go
type OrganizationMember struct {
	ID        string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	OrgID     string     `json:"org_id" gorm:"type:varchar(36);not null;uniqueIndex:idx_org_member"`
	UserID    string     `json:"user_id" gorm:"type:varchar(36);not null;uniqueIndex:idx_org_member"`
	Role      string     `json:"role" gorm:"type:varchar(50);not null;default:'member'"`
	JoinedAt  time.Time  `json:"joined_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}
```

#### OrganizationMemberRepository

```go
type OrganizationMemberRepository interface {
	Create(ctx context.Context, member *OrganizationMember) error
	FindByOrgAndUser(ctx context.Context, orgID, userID string) (*OrganizationMember, error)
	ListByOrg(ctx context.Context, orgID string, opts MemberListOpts) ([]*OrganizationMember, int64, error)
	ListByUser(ctx context.Context, userID string) ([]*OrganizationMember, error)
	Update(ctx context.Context, member *OrganizationMember) error
	Delete(ctx context.Context, id string) error
	DeleteByOrgAndUser(ctx context.Context, orgID, userID string) error
	CountByOrg(ctx context.Context, orgID string) (int64, error)
}
```

---

### OrgInvitation

Table: `org_invitations`

Represents a pending invitation to join an organization.

```go
type OrgInvitation struct {
	ID         string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	OrgID      string     `json:"org_id" gorm:"type:varchar(36);not null"`
	Email      string     `json:"email" gorm:"type:varchar(255);not null"`
	Role       string     `json:"role" gorm:"type:varchar(50);not null;default:'member'"`
	InviterID  string     `json:"inviter_id" gorm:"type:varchar(36);not null"`
	Token      string     `json:"-" gorm:"type:varchar(255);uniqueIndex;not null"`
	Status     string     `json:"status" gorm:"type:varchar(20);not null;default:'pending'"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
}
```

#### OrgInvitationRepository

```go
type OrgInvitationRepository interface {
	Create(ctx context.Context, invitation *OrgInvitation) error
	FindByID(ctx context.Context, id string) (*OrgInvitation, error)
	FindByToken(ctx context.Context, token string) (*OrgInvitation, error)
	FindByOrgAndEmail(ctx context.Context, orgID, email string) (*OrgInvitation, error)
	ListByOrg(ctx context.Context, orgID string, opts OrgInvitationListOpts) ([]*OrgInvitation, int64, error)
	ListPendingByEmail(ctx context.Context, email string) ([]*OrgInvitation, error)
	Update(ctx context.Context, invitation *OrgInvitation) error
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}
```

---

### Invitation (standalone)

Table: `invitations`

Represents a standalone platform invitation (not org-scoped).

```go
type Invitation struct {
	ID         string     `json:"id" gorm:"primaryKey;type:varchar(36)"`
	Email      string     `json:"email" gorm:"type:varchar(255);not null"`
	Purpose    string     `json:"purpose" gorm:"type:varchar(100);not null;default:'platform'"`
	InviterID  string     `json:"inviter_id" gorm:"type:varchar(36);not null"`
	Token      string     `json:"-" gorm:"type:varchar(255);uniqueIndex;not null"`
	Status     string     `json:"status" gorm:"type:varchar(20);not null;default:'pending'"`
	Metadata   string     `json:"metadata,omitempty" gorm:"type:text"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
}
```

**Invitation status constants** (shared between standalone and org invitations):

| Constant | Value |
|---|---|
| `InvitationStatusPending` | `"pending"` |
| `InvitationStatusAccepted` | `"accepted"` |
| `InvitationStatusDeclined` | `"declined"` |
| `InvitationStatusExpired` | `"expired"` |

#### InvitationRepository

```go
type InvitationRepository interface {
	Create(ctx context.Context, invitation *Invitation) error
	FindByID(ctx context.Context, id string) (*Invitation, error)
	FindByToken(ctx context.Context, token string) (*Invitation, error)
	FindPendingByEmail(ctx context.Context, email, purpose string) (*Invitation, error)
	ListByInviter(ctx context.Context, inviterID string, opts InvitationListOpts) ([]*Invitation, int64, error)
	ListPendingByEmail(ctx context.Context, email string) ([]*Invitation, error)
	Update(ctx context.Context, invitation *Invitation) error
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}
```

---

## Listing Options

All list/search repository methods accept a per-entity options struct that embeds the base `ListingOpts`. These control pagination and sorting.

### ListingOpts (Base)

```go
type ListingOpts struct {
	Offset    int
	Limit     int
	SortField string
	SortDir   string // "asc" or "desc"
}
```

Defaults (from `DefaultListingOpts()`): Offset=0, Limit=20, SortField=`"created_at"`, SortDir=`"desc"`.

The `Normalize(maxLimit, allowedSortFields)` method clamps values to safe ranges: limit to `[1, maxLimit]`, offset to `[0, +inf)`, sort direction to `"asc"` or `"desc"`, and sort field to a member of the allowlist (falling back to `"created_at"`).

### Per-Entity Options

| Type | Embeds | Extra Fields | Allowed Sort Fields |
|---|---|---|---|
| `UserListOpts` | `ListingOpts` | `Query string` -- search name/email/username | `created_at`, `email`, `username`, `name` |
| `SessionListOpts` | `ListingOpts` | *(none)* | `created_at`, `expires_at`, `ip_address` |
| `AuditLogListOpts` | `ListingOpts` | *(none)* | `created_at`, `action`, `severity`, `actor_id` |
| `OrganizationListOpts` | `ListingOpts` | `OwnerID string`, `Query string` | `created_at`, `name` |
| `MemberListOpts` | `ListingOpts` | `Role string` | `joined_at`, `role` |
| `InvitationListOpts` | `ListingOpts` | `Status string` | `created_at`, `expires_at`, `status` |

Each per-entity type has its own `Normalize(maxLimit int)` method that delegates to `ListingOpts.Normalize` with the correct sort field allowlist for that entity.

## Passkey Models

Registered credentials live in `passkey_credentials`. Credential IDs and public keys are binary; the private key remains with the authenticator. The HTTP DTO intentionally exposes less data than this storage model.

### PasskeyCredential

```go
type PasskeyCredential struct {
	ID                string     `json:"id" gorm:"primaryKey"`
	UserID            string     `json:"user_id" gorm:"not null;index"`
	CredentialID      []byte     `json:"credential_id" gorm:"uniqueIndex;not null"`
	PublicKey         []byte     `json:"public_key" gorm:"not null"`
	AttestationType   string     `json:"attestation_type"`
	AttestationFormat string     `json:"attestation_format"`
	AAGUID            []byte     `json:"aaguid"`
	SignCount         uint32     `json:"sign_count" gorm:"not null;default:0"`
	Transports        string     `json:"transports"` // comma-separated ("usb,nfc,internal,hybrid")
	BackupEligible    bool       `json:"backup_eligible" gorm:"not null;default:false"`
	BackupState       bool       `json:"backup_state" gorm:"not null;default:false"`
	UserPresent       bool       `json:"user_present" gorm:"not null;default:false"`
	UserVerified      bool       `json:"user_verified" gorm:"not null;default:false"`
	Name              string     `json:"name"` // user-friendly label ("iPhone 15", "YubiKey 5")
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}
```

### PasskeyRepository

```go
type PasskeyRepository interface {
	Create(ctx context.Context, cred *PasskeyCredential) error
	FindByID(ctx context.Context, id string) (*PasskeyCredential, error)
	FindByCredentialID(ctx context.Context, credentialID []byte) (*PasskeyCredential, error)
	ListByUserID(ctx context.Context, userID string) ([]*PasskeyCredential, error)
	// UpdateSignCount atomically advances a nonzero counter; non-increasing
	// values conflict. Zero-to-zero is permitted for counterless authenticators.
	UpdateSignCount(ctx context.Context, id string, signCount uint32) error
	UpdateLastUsed(ctx context.Context, id string, at time.Time) error
	UpdateName(ctx context.Context, id, name string) error
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
}
```

## Atomic Repository Capabilities

Security flows require conditional consumption/rotation and targeted updates. A read followed by an unconditional write is not a substitute for these contracts. Session rotation preserves the session ID and absolute expiry; token rotation replaces only the expected live record.

### TokenRotator

```go
type TokenRotator interface {
	Rotate(ctx context.Context, expected *Token, replacement *Token) error
}
```

### SessionRotator

```go
type SessionRotator interface {
	RotateToken(ctx context.Context, oldToken string, session *Session) error
}
```

### UserCredentialMutator

```go
type UserCredentialMutator interface {
	RevokeTokens(context.Context, string) error
	ChangePassword(context.Context, string, string, string) error
	RecordLogin(context.Context, string, int, time.Time) error
}
```

### UserAuthenticationMutator

```go
type UserAuthenticationMutator interface {
	RecordFailedLogin(context.Context, string, int, int, time.Duration) (*User, error)
	VerifyContact(context.Context, string, string, bool) error
}
```

### UserProfileMutator

```go
type UserProfileMutator interface {
	UpdateProfile(context.Context, string, string, string, string) error
}
```

## Verified Authentication State

These types live in `pkg/types`. `Principal` is verified state, `GrantContext` is persisted assurance, and `AuthenticationResult` is the transport-independent completion result. HTTP endpoints retain their own DTO envelopes. Never populate trusted authentication evidence from an unverified request.

### Principal

```go
type Principal struct {
	Methods         []string
	OrganizationID  string
	UserID          string
	RealmID         string
	SessionID       string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	TokenVersion    int
}
```

### GrantContext

```go
type GrantContext struct {
	AuthenticatedAt time.Time `json:"authenticated_at"`
	Methods         []string  `json:"methods"`
	TokenVersion    int       `json:"token_version"`
	OrganizationID  string    `json:"organization_id,omitempty"`
}
```

### AuthenticationResult

```go
type AuthenticationResult struct {
	UserID       string
	Status       AuthenticationStatus
	AccessToken  string
	RefreshToken string
	SessionID    string
	ExpiresIn    int64
	Challenges   []LoginChallenge
	Data         map[string]interface{}
}
```

### AuthenticationTransaction

```go
type AuthenticationTransaction struct {
	Version         int                    `json:"version"`
	RealmID         string                 `json:"realm_id"`
	UserID          string                 `json:"user_id"`
	TokenVersion    int                    `json:"token_version"`
	AuthenticatedAt time.Time              `json:"authenticated_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
	Methods         []string               `json:"methods"`
	Required        []LoginChallengeType   `json:"required"`
	Claims          map[string]interface{} `json:"claims,omitempty"`
}
```

`Token.Data` stores authentication continuation data; `Session.AuthData` stores grant assurance. Both are hidden from JSON. Token-purpose strings also include `2fa_pending`, `passkey_registration`, and `passkey_login`. Preserve these fields in custom repositories and apply the associated migrations.
