# Audit Module - Future Plan

## Current State

User self-service audit endpoints:
- Get my audit logs (actor + target merged, deduplicated)
- Get my login history (filtered by `auth.login.*`)
- Get my profile changes (filtered by `user.*` + `auth.password.*`)
- Get my security events (filtered by `security.*` + `auth.2fa.*`)

Admin audit endpoints:
- List all audit logs (paginated)
- Get audit logs by user ID (actor + target merged)
- Get audit logs by action type

Event-driven log creation:
- Auth events (login success/fail, logout, password change, 2FA)
- User events (profile update, email/phone change, avatar, email verified)
- Admin events (user created/updated/deleted/suspended, role assigned/revoked)
- Security events (suspicious login, account locked, session/token revoked)

Configurable retention policies + cleanup job.

---

## Phase 1: Improve Querying (Short-term)

### 1.1 Filtering & Search
Add query params to listing endpoints for richer filtering.
- `GET /me/audit?action=auth.login.*&severity=warning&from=2025-01-01&to=2025-02-01`
- `GET /admin/audit?actor_id=...&target_id=...&severity=critical&action=admin.*`
- Date range filtering (`from`, `to` query params)
- Severity filtering (`info`, `warning`, `critical`)
- Full-text search on `details` field
- Extend `AuditLogListOpts` with filter fields (follows listing pattern from CLAUDE.md)

### 1.2 Audit Export
Export audit logs for compliance and reporting.
- Route already defined: `RouteAdminExportAudit`
- `GET /admin/audit/export?format=csv&from=...&to=...`
- Supported formats: CSV, JSON
- Streaming response for large datasets
- Same filters as listing endpoint
- Rate limited to prevent abuse

### 1.3 Severity-Based Endpoints
- `GET /admin/audit/severity/{level}` — filter by severity (info/warning/critical)
- Service method `GetSecurityAuditLogs` already exists but has no handler

---

## Phase 2: Real-time & Alerts (Medium-term)

### 2.1 Webhook Notifications
Push critical audit events to external systems.
- POST to webhook URL with signed payload on matching events
- Retry with exponential backoff on failure
- Filter by severity (`critical` only, `warning+`, etc.)

### 2.2 User Activity Summary
Aggregated view of user activity over time.
- `GET /me/audit/summary` — weekly/monthly activity summary
- `GET /admin/audit/users/{id}/summary` — admin view of user activity

---

## Phase 3: Compliance & Retention (Long-term)

### 3.1 Retention Policy Management
Admin-configurable retention from the API.
- `GET /admin/audit/retention` — current retention policies
- `PUT /admin/audit/retention` — update retention policies
- Per-action-pattern retention (e.g., `auth.*` = 90 days, `security.*` = forever)

### 3.2 GDPR Right to Erasure
Handle audit log redaction for user deletion.
- When user is deleted, anonymize their audit logs (replace PII with `[redacted]`)
- Keep the log structure intact for compliance (action, timestamp, severity)
- `POST /admin/audit/redact/{user_id}` — manually trigger redaction
