---
id: models
title: Models Reference
sidebar_label: Models
sidebar_position: 4
---

# Models Reference

All GoAuth data models live in the `pkg/models` package. Each model maps to a database table (via GORM tags) and has an associated repository interface for data access.

All entity IDs are UUIDs (v7). GoAuth does not use soft deletes.

---

## Sentinel Error

```go
var ErrNotFound = errors.New("record not found")
```

Repository methods return `models.ErrNotFound` when the requested record does not exist. Check for it with:

```go
if errors.Is(err, models.ErrNotFound) {
    // record does not exist
}
```

This is a standard `error`, not a `*types.GoAuthError`. It is used at the storage layer, while `*types.GoAuthError` is used at the service/handler layer.

---

## Core Models

### User

Table: `users`

```go
type User struct {
    ID                  string     `json:"id" gorm:"primaryKey"`
    Name                string     `json:"name"`
    FirstName           string     `json:"first_name"`
    LastName            string     `json:"last_name"`
    Email               string     `json:"email" gorm:"uniqueIndex;not null"`
    Username            string     `json:"username" gorm:"uniqueIndex"`
    PasswordHash        string     `json:"-" gorm:"column:password;not null"`
    Avatar              string     `json:"avatar"`
    PhoneNumber         string     `json:"phone_number"`
    Active              bool       `json:"active" gorm:"default:true"`
    EmailVerified       bool       `json:"email_verified" gorm:"default:false"`
    PhoneNumberVerified bool       `json:"phone_number_verified" gorm:"default:false"`
    IsSuperAdmin        bool       `json:"is_super_admin" gorm:"default:false;not null;index"`
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
| `TokenVersion` | Incremented to invalidate all existing stateless tokens for this user. |
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
    ID                string     `json:"id" gorm:"primaryKey"`
    UserID            string     `json:"user_id" gorm:"not null;index"`
    Provider          string     `json:"provider" gorm:"not null;index"`
    ProviderAccountID string     `json:"provider_account_id" gorm:"not null"`
    Type              string     `json:"type" gorm:"not null"`
    AccessToken       string     `json:"-" gorm:"type:text"`
    RefreshToken      string     `json:"-" gorm:"type:text"`
    ExpiresAt         *time.Time `json:"expires_at,omitempty"`
    TokenType         string     `json:"token_type,omitempty"`
    Scope             string     `json:"scope,omitempty"`
    IDToken           string     `json:"-" gorm:"type:text"`
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
    Create(ctx context.Context, account *Account) error
    FindByID(ctx context.Context, id string) (*Account, error)
    FindByProviderAndAccountID(ctx context.Context, provider, providerAccountID string) (*Account, error)
    FindByUserID(ctx context.Context, userID string) ([]*Account, error)
    FindByUserIDAndProvider(ctx context.Context, userID, provider string) (*Account, error)
    Update(ctx context.Context, account *Account) error
    Delete(ctx context.Context, id string) error
    DeleteByUserIDAndProvider(ctx context.Context, userID, provider string) error
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
    ID        string    `json:"id" gorm:"primaryKey"`
    UserID    string    `json:"user_id" gorm:"uniqueIndex;not null"`
    Secret    string    `json:"-" gorm:"not null"`
    Enabled   bool      `json:"enabled" gorm:"default:false"`
    Verified  bool      `json:"verified" gorm:"default:false"`
    Method    string    `json:"method" gorm:"default:'totp'"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
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
    Code      string     `json:"-" gorm:"not null"`
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
    Action     string    `json:"action" gorm:"not null;index"`
    ActorID    string    `json:"actor_id" gorm:"not null;index"`
    ActorType  string    `json:"actor_type" gorm:"default:'user'"`
    TargetID   *string   `json:"target_id,omitempty" gorm:"index"`
    TargetType *string   `json:"target_type,omitempty"`
    Details    string    `json:"details" gorm:"type:text"`
    Metadata   string    `json:"metadata,omitempty" gorm:"type:jsonb"`
    Severity   string    `json:"severity" gorm:"default:'info';index"`
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
    Create(ctx context.Context, log *AuditLog) error
    FindByActorID(ctx context.Context, actorID string, opts AuditLogListOpts) ([]*AuditLog, int64, error)
    FindByTargetID(ctx context.Context, targetID string, opts AuditLogListOpts) ([]*AuditLog, int64, error)
    FindByAction(ctx context.Context, action string, opts AuditLogListOpts) ([]*AuditLog, int64, error)
    FindBySeverity(ctx context.Context, severity string, opts AuditLogListOpts) ([]*AuditLog, int64, error)
    FindByOrganizationID(ctx context.Context, orgID string, opts AuditLogListOpts) ([]*AuditLog, int64, error)
    List(ctx context.Context, opts AuditLogListOpts) ([]*AuditLog, int64, error)
    DeleteOlderThan(ctx context.Context, before time.Time) error
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
