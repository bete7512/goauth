package services

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/internal/modules/admin/models"
	coreModels "github.com/bete7512/goauth/internal/modules/core/models"
	"github.com/bete7512/goauth/pkg/config"
)

type AdminService struct {
	deps           config.ModuleDependencies
	auditLogRepo   models.AuditLogRepository
	userRepository coreModels.UserRepository // Access to core module's UserRepository
}

func NewAdminService(
	deps config.ModuleDependencies,
	auditLogRepo models.AuditLogRepository,
	userRepo coreModels.UserRepository,
) *AdminService {
	return &AdminService{
		deps:           deps,
		auditLogRepo:   auditLogRepo,
		userRepository: userRepo,
	}
}

// Example: List all users (using core's UserRepository)
func (s *AdminService) ListUsers(ctx context.Context, limit, offset int) ([]*coreModels.User, error) {
	users, err := s.userRepository.List(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Log this admin action
	_ = s.auditLogRepo.Create(ctx, &models.AuditLog{
		Action:  "admin.users.list",
		UserID:  0, // Get from context
		Details: fmt.Sprintf("Listed %d users", len(users)),
	})

	return users, nil
}

// Example: Get user by ID
func (s *AdminService) GetUser(ctx context.Context, userID string) (*coreModels.User, error) {
	user, err := s.userRepository.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Log this admin action
	_ = s.auditLogRepo.Create(ctx, &models.AuditLog{
		Action:  "admin.users.get",
		UserID:  0, // Get from context
		Details: fmt.Sprintf("Viewed user %s", userID),
	})

	return user, nil
}

// Example: Update user
func (s *AdminService) UpdateUser(ctx context.Context, user *coreModels.User) error {
	if err := s.userRepository.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Log this admin action
	_ = s.auditLogRepo.Create(ctx, &models.AuditLog{
		Action:  "admin.users.update",
		UserID:  0, // Get from context
		Details: fmt.Sprintf("Updated user %s", user.ID),
	})

	return nil
}

// Example: Delete user
func (s *AdminService) DeleteUser(ctx context.Context, userID string) error {
	if err := s.userRepository.Delete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Log this admin action
	_ = s.auditLogRepo.Create(ctx, &models.AuditLog{
		Action:  "admin.users.delete",
		UserID:  0, // Get from context
		Details: fmt.Sprintf("Deleted user %s", userID),
	})

	return nil
}

// Get audit logs for a specific user
func (s *AdminService) GetUserAuditLogs(ctx context.Context, userID string, limit, offset int) ([]*models.AuditLog, error) {
	return s.auditLogRepo.FindByUserID(ctx, userID, limit, offset)
}
