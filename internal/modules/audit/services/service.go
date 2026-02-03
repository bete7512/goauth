package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
)

type AuditService struct {
	deps          config.ModuleDependencies
	auditLogRepo  models.AuditLogRepository
	retentionDays map[string]int
}

func NewAuditService(
	deps config.ModuleDependencies,
	auditLogRepo models.AuditLogRepository,
	retentionDays map[string]int,
) *AuditService {
	return &AuditService{
		deps:          deps,
		auditLogRepo:  auditLogRepo,
		retentionDays: retentionDays,
	}
}

// CreateAuditLog creates a new audit log entry
func (s *AuditService) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	return s.auditLogRepo.Create(ctx, log)
}

// GetMyAuditLogs retrieves audit logs for the current user (both as actor and target)
func (s *AuditService) GetMyAuditLogs(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error) {
	// Get logs where user is the actor
	actorLogs, err := s.auditLogRepo.FindByActorID(ctx, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get actor logs: %w", err)
	}

	// Get logs where user is the target
	targetLogs, err := s.auditLogRepo.FindByTargetID(ctx, userID, limit/2, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get target logs: %w", err)
	}

	// Merge and deduplicate
	merged := mergeLogs(actorLogs, targetLogs, limit)
	return merged, nil
}

// GetMyLogins retrieves login history for the current user
func (s *AuditService) GetMyLogins(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error) {
	allLogs, err := s.auditLogRepo.FindByActorID(ctx, userID, limit*2, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}

	// Filter for login-related actions
	var loginLogs []*models.AuditLog
	for _, log := range allLogs {
		if strings.HasPrefix(log.Action, "auth.login") {
			loginLogs = append(loginLogs, log)
			if len(loginLogs) >= limit {
				break
			}
		}
	}

	return loginLogs, nil
}

// GetMyChanges retrieves profile change history for the current user
func (s *AuditService) GetMyChanges(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error) {
	allLogs, err := s.auditLogRepo.FindByActorID(ctx, userID, limit*2, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}

	// Filter for profile change actions
	var changeLogs []*models.AuditLog
	for _, log := range allLogs {
		if strings.HasPrefix(log.Action, "user.") || strings.HasPrefix(log.Action, "auth.password") {
			changeLogs = append(changeLogs, log)
			if len(changeLogs) >= limit {
				break
			}
		}
	}

	return changeLogs, nil
}

// GetMySecurity retrieves security events for the current user
func (s *AuditService) GetMySecurity(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error) {
	allLogs, err := s.auditLogRepo.FindByActorID(ctx, userID, limit*2, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}

	// Filter for security events
	var securityLogs []*models.AuditLog
	for _, log := range allLogs {
		if strings.HasPrefix(log.Action, "security.") || strings.HasPrefix(log.Action, "auth.2fa") {
			securityLogs = append(securityLogs, log)
			if len(securityLogs) >= limit {
				break
			}
		}
	}

	return securityLogs, nil
}

// Admin methods

// ListAllAuditLogs retrieves all audit logs (admin only)
func (s *AuditService) ListAllAuditLogs(ctx context.Context, limit, offset int) ([]*models.AuditLog, error) {
	return s.auditLogRepo.List(ctx, limit, offset)
}

// GetUserAuditLogs retrieves audit logs for a specific user (admin only)
func (s *AuditService) GetUserAuditLogs(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error) {
	// Get logs where user is the actor
	actorLogs, err := s.auditLogRepo.FindByActorID(ctx, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get actor logs: %w", err)
	}

	// Get logs where user is the target
	targetLogs, err := s.auditLogRepo.FindByTargetID(ctx, userID, limit/2, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get target logs: %w", err)
	}

	// Merge
	merged := mergeLogs(actorLogs, targetLogs, limit)
	return merged, nil
}

// GetAuditLogsByAction retrieves audit logs by action type (admin only)
func (s *AuditService) GetAuditLogsByAction(ctx context.Context, action string, limit, offset int) ([]*models.AuditLog, error) {
	return s.auditLogRepo.FindByAction(ctx, action, limit, offset)
}

// GetSecurityAuditLogs retrieves security-related audit logs (admin only)
func (s *AuditService) GetSecurityAuditLogs(ctx context.Context, limit, offset int) ([]*models.AuditLog, error) {
	return s.auditLogRepo.FindBySeverity(ctx, "critical", limit, offset)
}

// CleanupOldLogs deletes old audit logs based on retention policies
func (s *AuditService) CleanupOldLogs(ctx context.Context) error {
	for actionPattern, days := range s.retentionDays {
		if days > 0 {
			cutoff := time.Now().AddDate(0, 0, -days)
			if err := s.auditLogRepo.DeleteByActionOlderThan(ctx, actionPattern, cutoff); err != nil {
				return fmt.Errorf("failed to cleanup logs for %s: %w", actionPattern, err)
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
