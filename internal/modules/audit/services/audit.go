package services

//go:generate mockgen -destination=../../../mocks/mock_audit_service.go -package=mocks github.com/bete7512/goauth/internal/modules/audit/services AuditService

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type AuditService interface {
	CreateAuditLog(ctx context.Context, log *models.AuditLog) *types.GoAuthError
	GetMyAuditLogs(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError)
	GetMyLogins(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError)
	GetMyChanges(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError)
	GetMySecurity(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError)
	ListAllAuditLogs(ctx context.Context, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError)
	GetUserAuditLogs(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError)
	GetAuditLogsByAction(ctx context.Context, action string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError)
	CleanupOldLogs(ctx context.Context) *types.GoAuthError
}

type auditService struct {
	deps          config.ModuleDependencies
	auditLogRepo  models.AuditLogRepository
	retentionDays map[string]int
}

func NewAuditService(
	deps config.ModuleDependencies,
	auditLogRepo models.AuditLogRepository,
	retentionDays map[string]int,
) *auditService {
	return &auditService{
		deps:          deps,
		auditLogRepo:  auditLogRepo,
		retentionDays: retentionDays,
	}
}

// CreateAuditLog creates a new audit log entry
func (s *auditService) CreateAuditLog(ctx context.Context, log *models.AuditLog) *types.GoAuthError {
	if err := s.auditLogRepo.Create(ctx, log); err != nil {
		return types.NewInternalError(fmt.Sprintf("failed to create audit log: %v", err))
	}
	return nil
}

// GetMyAuditLogs retrieves audit logs for the current user (both as actor and target)
func (s *auditService) GetMyAuditLogs(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError) {
	// Get logs where user is the actor
	actorLogs, _, err := s.auditLogRepo.FindByActorID(ctx, userID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError(fmt.Sprintf("failed to get actor logs: %v", err))
	}

	// Get logs where user is the target
	targetOpts := opts
	targetLogs, _, err := s.auditLogRepo.FindByTargetID(ctx, userID, targetOpts)
	if err != nil {
		return nil, 0, types.NewInternalError(fmt.Sprintf("failed to get target logs: %v", err))
	}

	// Merge and deduplicate
	merged := mergeLogs(actorLogs, targetLogs, opts.Limit)
	return merged, int64(len(merged)), nil
}

// GetMyLogins retrieves login history for the current user
func (s *auditService) GetMyLogins(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError) {
	fetchOpts := opts
	fetchOpts.Limit = opts.Limit * 2
	allLogs, _, err := s.auditLogRepo.FindByActorID(ctx, userID, fetchOpts)
	if err != nil {
		return nil, 0, types.NewInternalError(fmt.Sprintf("failed to get logs: %v", err))
	}

	// Filter for login-related actions
	var loginLogs []*models.AuditLog
	// TODO: this is disaster filter have to be sent 
	for _, log := range allLogs {
		if strings.HasPrefix(log.Action, "auth.login") {
			loginLogs = append(loginLogs, log)
			if len(loginLogs) >= opts.Limit {
				break
			}
		}
	}

	return loginLogs, int64(len(loginLogs)), nil
}

// GetMyChanges retrieves profile change history for the current user
func (s *auditService) GetMyChanges(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError) {
	fetchOpts := opts
	fetchOpts.Limit = opts.Limit * 2
	allLogs, _, err := s.auditLogRepo.FindByActorID(ctx, userID, fetchOpts)
	if err != nil {
		return nil, 0, types.NewInternalError(fmt.Sprintf("failed to get logs: %v", err))
	}

	// Filter for profile change actions
	var changeLogs []*models.AuditLog
	for _, log := range allLogs {
		if strings.HasPrefix(log.Action, "user.") || strings.HasPrefix(log.Action, "auth.password") {
			changeLogs = append(changeLogs, log)
			if len(changeLogs) >= opts.Limit {
				break
			}
		}
	}

	return changeLogs, int64(len(changeLogs)), nil
}

// GetMySecurity retrieves security events for the current user
func (s *auditService) GetMySecurity(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError) {
	fetchOpts := opts
	fetchOpts.Limit = opts.Limit * 2
	allLogs, _, err := s.auditLogRepo.FindByActorID(ctx, userID, fetchOpts)
	if err != nil {
		return nil, 0, types.NewInternalError(fmt.Sprintf("failed to get logs: %v", err))
	}

	// Filter for security events
	var securityLogs []*models.AuditLog
	for _, log := range allLogs {
		if strings.HasPrefix(log.Action, "security.") || strings.HasPrefix(log.Action, "auth.2fa") {
			securityLogs = append(securityLogs, log)
			if len(securityLogs) >= opts.Limit {
				break
			}
		}
	}

	return securityLogs, int64(len(securityLogs)), nil
}

// Admin methods

// ListAllAuditLogs retrieves all audit logs (admin only)
func (s *auditService) ListAllAuditLogs(ctx context.Context, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError) {
	logs, total, err := s.auditLogRepo.List(ctx, opts)
	if err != nil {
		return nil, 0, types.NewInternalError(fmt.Sprintf("failed to list audit logs: %v", err))
	}
	return logs, total, nil
}

// GetUserAuditLogs retrieves audit logs for a specific user (admin only)
func (s *auditService) GetUserAuditLogs(ctx context.Context, userID string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError) {
	// Get logs where user is the actor
	actorLogs, _, err := s.auditLogRepo.FindByActorID(ctx, userID, opts)
	if err != nil {
		return nil, 0, types.NewInternalError(fmt.Sprintf("failed to get actor logs: %v", err))
	}

	// Get logs where user is the target
	targetOpts := opts
	targetOpts.Limit = opts.Limit / 2
	targetOpts.Offset = 0
	targetLogs, _, err := s.auditLogRepo.FindByTargetID(ctx, userID, targetOpts)
	if err != nil {
		return nil, 0, types.NewInternalError(fmt.Sprintf("failed to get target logs: %v", err))
	}

	// Merge
	merged := mergeLogs(actorLogs, targetLogs, opts.Limit)
	return merged, int64(len(merged)), nil
}

// GetAuditLogsByAction retrieves audit logs by action type (admin only)
func (s *auditService) GetAuditLogsByAction(ctx context.Context, action string, opts models.AuditLogListOpts) ([]*models.AuditLog, int64, *types.GoAuthError) {
	logs, total, err := s.auditLogRepo.FindByAction(ctx, action, opts)
	if err != nil {
		return nil, 0, types.NewInternalError(fmt.Sprintf("failed to get audit logs by action: %v", err))
	}
	return logs, total, nil
}

// CleanupOldLogs deletes old audit logs based on retention policies
func (s *auditService) CleanupOldLogs(ctx context.Context) *types.GoAuthError {
	for actionPattern, days := range s.retentionDays {
		if days > 0 {
			cutoff := time.Now().AddDate(0, 0, -days)
			if err := s.auditLogRepo.DeleteByActionOlderThan(ctx, actionPattern, cutoff); err != nil {
				return types.NewInternalError(fmt.Sprintf("failed to cleanup logs for %s: %v", actionPattern, err))
			}
		}
	}
	return nil
}

// mergeLogs combines two slices of audit logs and removes duplicates
func mergeLogs(logs1, logs2 []*models.AuditLog, limit int) []*models.AuditLog {
	seen := make(map[string]bool)
	var result []*models.AuditLog

	for _, log := range logs1 {
		if !seen[log.ID] {
			seen[log.ID] = true
			result = append(result, log)
			if len(result) >= limit {
				return result
			}
		}
	}

	for _, log := range logs2 {
		if !seen[log.ID] {
			seen[log.ID] = true
			result = append(result, log)
			if len(result) >= limit {
				return result
			}
		}
	}

	return result
}
