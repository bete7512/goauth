package audit

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/bete7512/goauth/internal/modules/audit/handlers"
	"github.com/bete7512/goauth/internal/modules/audit/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

//go:embed docs/swagger.yml
var swaggerSpec []byte

type AuditModule struct {
	deps     config.ModuleDependencies
	handlers *handlers.AuditHandler
	service  *services.AuditService
	config   *Config
}

type Config struct {
	// Optional custom repository for testing
	AuditLogRepository models.AuditLogRepository

	// Retention policies (days to keep logs, -1 = keep forever)
	RetentionDays map[string]int

	// What to track
	TrackAuthEvents     bool
	TrackUserEvents     bool
	TrackAdminEvents    bool
	TrackSecurityEvents bool

	// Sampling rate (1.0 = 100%, 0.5 = 50%)
	SampleRate float64
}

var _ config.Module = (*AuditModule)(nil)

func New(cfg *Config) *AuditModule {
	if cfg == nil {
		cfg = &Config{
			TrackAuthEvents:     true,
			TrackUserEvents:     true,
			TrackAdminEvents:    true,
			TrackSecurityEvents: true,
			SampleRate:          1.0,
			RetentionDays: map[string]int{
				"auth.*":     90,  // Keep 90 days
				"user.*":     90,  // Keep 90 days
				"admin.*":    365, // Keep 1 year
				"security.*": -1,  // Keep forever
			},
		}
	}
	return &AuditModule{
		config: cfg,
	}
}

func (m *AuditModule) Init(ctx context.Context, deps config.ModuleDependencies) error {
	m.deps = deps

	// Get AuditLog repository from AdminStorage
	var auditLogRepo models.AuditLogRepository
	if m.config.AuditLogRepository != nil {
		auditLogRepo = m.config.AuditLogRepository
	} else {
		// Get from admin storage (audit logs stored there)
		if deps.Storage != nil {
			adminStorage := deps.Storage.Admin()
			if adminStorage != nil {
				auditLogRepo = adminStorage.AuditLogs()
			}
		}
		if auditLogRepo == nil {
			return fmt.Errorf("audit module: audit log repository not available - ensure AdminStorage is configured")
		}
	}

	// Initialize service
	m.service = services.NewAuditService(deps, auditLogRepo, m.config.RetentionDays)

	// Initialize handlers
	m.handlers = handlers.NewAuditHandler(deps, m.service)

	return nil
}

func (m *AuditModule) Name() string {
	return string(types.AuditModule)
}

func (m *AuditModule) Routes() []config.RouteInfo {
	if m.handlers == nil {
		return nil
	}
	return m.handlers.GetRoutes()
}

func (m *AuditModule) Middlewares() []config.MiddlewareConfig {
	return []config.MiddlewareConfig{}
}

func (m *AuditModule) Models() []any {
	return []any{
		&models.AuditLog{},
	}
}

func (m *AuditModule) RegisterHooks(events types.EventBus) error {
	// Subscribe to authentication events
	if m.config.TrackAuthEvents {
		m.subscribeAuthEvents(events)
	}

	// Subscribe to user profile events
	if m.config.TrackUserEvents {
		m.subscribeUserEvents(events)
	}

	// Subscribe to admin events
	if m.config.TrackAdminEvents {
		m.subscribeAdminEvents(events)
	}

	// Subscribe to security events
	if m.config.TrackSecurityEvents {
		m.subscribeSecurityEvents(events)
	}

	return nil
}

func (m *AuditModule) subscribeAuthEvents(events types.EventBus) {
	// Login success
	events.Subscribe(types.EventAuthLoginSuccess, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "auth.login.success", "info")
	}))

	// Login failed
	events.Subscribe(types.EventAuthLoginFailed, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "auth.login.failed", "warning")
	}))

	// Logout
	events.Subscribe(types.EventAuthLogout, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "auth.logout", "info")
	}))

	// Password changed
	events.Subscribe(types.EventAuthPasswordChanged, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "auth.password.changed", "info")
	}))

	// 2FA events
	events.Subscribe(types.EventAuth2FAEnabled, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "auth.2fa.enabled", "info")
	}))

	events.Subscribe(types.EventAuth2FADisabled, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "auth.2fa.disabled", "warning")
	}))
}

func (m *AuditModule) subscribeUserEvents(events types.EventBus) {
	events.Subscribe(types.EventUserProfileUpdated, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "user.profile.updated", "info")
	}))

	events.Subscribe(types.EventUserEmailChanged, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "user.email.changed", "info")
	}))

	events.Subscribe(types.EventUserEmailVerified, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "user.email.verified", "info")
	}))

	events.Subscribe(types.EventUserPhoneChanged, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "user.phone.changed", "info")
	}))

	events.Subscribe(types.EventUserAvatarUpdated, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "user.avatar.updated", "info")
	}))
}

func (m *AuditModule) subscribeAdminEvents(events types.EventBus) {
	events.Subscribe(types.EventAdminUserCreated, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "admin.user.created", "info")
	}))

	events.Subscribe(types.EventAdminUserUpdated, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "admin.user.updated", "info")
	}))

	events.Subscribe(types.EventAdminUserDeleted, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "admin.user.deleted", "warning")
	}))

	events.Subscribe(types.EventAdminUserSuspended, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "admin.user.suspended", "warning")
	}))

	events.Subscribe(types.EventAdminRoleAssigned, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "admin.role.assigned", "info")
	}))

	events.Subscribe(types.EventAdminRoleRevoked, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "admin.role.revoked", "warning")
	}))
}

func (m *AuditModule) subscribeSecurityEvents(events types.EventBus) {
	events.Subscribe(types.EventSecuritySuspiciousLogin, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "security.suspicious.login", "critical")
	}))

	events.Subscribe(types.EventSecurityAccountLocked, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "security.account.locked", "warning")
	}))

	events.Subscribe(types.EventSecuritySessionRevoked, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "security.session.revoked", "info")
	}))

	events.Subscribe(types.EventSecurityTokenInvalidated, types.EventHandler(func(ctx context.Context, event *types.Event) error {
		return m.createAuditLog(ctx, event, "security.token.invalidated", "info")
	}))
}

// createAuditLog is a helper to create audit log entries from events
func (m *AuditModule) createAuditLog(ctx context.Context, event *types.Event, action, severity string) error {
	// Extract data from event
	data, ok := event.Data.(map[string]interface{})
	if !ok {
		data = map[string]interface{}{}
	}

	// Get actor ID (user who performed the action)
	actorID, _ := data["actor_id"].(string)
	if actorID == "" {
		actorID, _ = data["user_id"].(string)
	}

	// Get target ID (resource affected)
	targetID, _ := data["target_id"].(string)
	targetType, _ := data["target_type"].(string)

	// Get details
	details, _ := data["details"].(string)
	if details == "" {
		details = fmt.Sprintf("Action: %s", action)
	}

	// Get metadata
	metadataBytes, _ := json.Marshal(data)
	metadata := string(metadataBytes)

	// Get IP and user agent
	ipAddress, _ := data["ip"].(string)
	userAgent, _ := data["user_agent"].(string)

	// Create audit log
	auditLog := &models.AuditLog{
		ID:        uuid.New().String(),
		Action:    action,
		ActorID:   actorID,
		ActorType: "user",
		Severity:  severity,
		Details:   details,
		Metadata:  metadata,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if targetID != "" {
		auditLog.TargetID = &targetID
	}
	if targetType != "" {
		auditLog.TargetType = &targetType
	}

	return m.service.CreateAuditLog(ctx, auditLog)
}

func (m *AuditModule) Dependencies() []string {
	// Audit module depends on core for authentication
	return []string{string(types.CoreModule)}
}

func (m *AuditModule) SwaggerSpec() []byte {
	return swaggerSpec
}
