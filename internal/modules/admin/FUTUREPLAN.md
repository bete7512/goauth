# Admin Module - Future Plan

## Current State (MVP)

Basic user CRUD for super admins:
- List users (paginated, searchable)
- Get user by ID
- Update user (partial update)
- Delete user (hard delete)
- Audit events emitted on update/delete
- Admin auth middleware (super admin only)

---

## Phase 1: Complete Core Admin (Short-term)

### 1.1 Create User (POST /admin/users)
Admin-created users (pre-verified, no signup flow).
- Route already defined: `RouteAdminCreateUser`
- Event already defined: `EventAdminUserCreated`
- Fields: email, name, password (or generate temp password), role, active
- Auto-verify email (admin trusts the creation)
- Emit `EventAdminUserCreated` audit event
- Send welcome/credential email via event hook

### 1.2 Suspend/Reactivate User
Toggle user active status with reason tracking.
- `PUT /admin/users/{id}/suspend` — sets `active=false`, records reason
- `PUT /admin/users/{id}/reactivate` — sets `active=true`
- Event already defined: `EventAdminUserSuspended`
- Invalidate all active sessions/tokens on suspend
- Store suspension reason in audit log metadata


### 1.3 Fix GetUser Error Handling
The FIXME at `services/users.go:49` — distinguish "not found" from internal errors.
- Option A: Define a storage-agnostic `ErrNotFound` sentinel in `pkg/types`
- Option B: Repository returns typed error, service checks with `errors.Is()`
- This affects all modules, not just admin

---

## Phase 2: User Lifecycle Management (Medium-term)

### 2.1 Bulk Operations
Operate on multiple users at once.
- `POST /admin/users/bulk/delete` — delete multiple users by ID list
- `POST /admin/users/bulk/suspend` — suspend multiple users
- `POST /admin/users/bulk/reactivate` — reactivate multiple users
- Request body: `{ "user_ids": ["id1", "id2", ...] }`
- Per-user audit events still emitted individually
- Partial success handling (some fail, some succeed)

### 2.2 User Invitation System
Invite users by email before they register.
- `POST /admin/users/invite` — send invitation email
- `POST /admin/users/invite/bulk` — invite multiple emails
- `GET /admin/users/invitations` — list pending invitations
- `DELETE /admin/users/invitations/{id}` — revoke invitation
- Invitation model: `email, token, expires_at, invited_by, accepted_at`
- Integrates with core signup — invited users skip email verification
- Configurable expiry (default 7 days)
- Resend capability

### 2.3 User Impersonation
Allow admin to act as another user (for debugging/support).
- `POST /admin/users/{id}/impersonate` — generate impersonation token
- `POST /admin/impersonate/stop` — end impersonation
- Impersonation token includes `impersonator_id` claim
- All actions during impersonation logged with both actor and impersonator
- Configurable: can be disabled entirely via config
- Time-limited sessions (max 1 hour)

### 2.4 Password Management
Admin-side password operations.
- `POST /admin/users/{id}/reset-password` — force password reset (sends email)
- `POST /admin/users/{id}/set-password` — directly set password (no email)
- `POST /admin/users/{id}/force-logout` — invalidate all sessions/tokens
- Increment `token_version` on forced password operations

---
## Phase 3: Analytics & Monitoring (Long-term)

### 4.1 Admin Dashboard Stats
Aggregate stats for admin dashboard UI.
- `GET /admin/stats` — overall system stats
  - Total users, active users, new signups (24h/7d/30d)
  - Failed login attempts, locked accounts
  - Active sessions count
- `GET /admin/stats/auth` — authentication stats
  - Login success/failure rates
  - Signup conversion rates
  - Password reset frequency

