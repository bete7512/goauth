package services

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type AdminService struct {
	deps           config.ModuleDependencies
	userRepository models.UserRepository
}

func NewAdminService(
	deps config.ModuleDependencies,
	userRepo models.UserRepository,
) *AdminService {
	return &AdminService{
		deps:           deps,
		userRepository: userRepo,
	}
}

// ListUsers lists all users with pagination
func (s *AdminService) ListUsers(ctx context.Context, opts models.UserListOpts) ([]*models.User, int64, error) {
	users, total, err := s.userRepository.List(ctx, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	return users, total, nil
}

// GetUser retrieves a user by ID
func (s *AdminService) GetUser(ctx context.Context, userID string) (*models.User, error) {
	user, err := s.userRepository.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// UpdateUser updates a user's information
func (s *AdminService) UpdateUser(ctx context.Context, user *models.User) error {
	adminUser, ok := ctx.Value(types.UserKey).(*models.User)
	if !ok || adminUser == nil {
		return fmt.Errorf("admin user not found in context")
	}

	if err := s.userRepository.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Emit audit event
	s.emitAuditEvent(
		ctx,
		types.EventAdminUserUpdated,
		adminUser.ID,
		user.ID,
		user.Email,
		fmt.Sprintf("Updated user %s (%s)", user.ID, user.Email),
	)

	return nil
}

// DeleteUser deletes a user by ID
func (s *AdminService) DeleteUser(ctx context.Context, userID string) error {
	// Get admin user for actor_id
	adminUser, ok := ctx.Value(types.UserKey).(*models.User)
	if !ok || adminUser == nil {
		return fmt.Errorf("admin user not found in context")
	}

	// Get user info before deletion for logging
	user, err := s.userRepository.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user before deletion: %w", err)
	}

	if err := s.userRepository.Delete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Emit audit event
	s.emitAuditEvent(
		ctx,
		types.EventAdminUserDeleted,
		adminUser.ID,
		userID,
		user.Email,
		fmt.Sprintf("Deleted user %s (%s)", userID, user.Email),
	)

	return nil
}

// emitAuditEvent emits an audit event to the event bus
// The audit module will pick it up and create the log entry
func (s *AdminService) emitAuditEvent(ctx context.Context, eventType types.EventType, actorID, targetID, targetEmail, details string) {
	// Extract admin user from context (set by AdminAuthMiddleware)
	user, ok := ctx.Value(types.UserKey).(*models.User)
	if !ok || user == nil {
		return
	}

	// Emit event asynchronously
	_ = s.deps.Events.EmitAsync(ctx, eventType, map[string]interface{}{
		"actor_id":     actorID,
		"target_id":    targetID,
		"target_type":  "user",
		"target_email": targetEmail,
		"details":      details,
	})
}
