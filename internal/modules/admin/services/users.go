package services

//go:generate mockgen -destination=../../../mocks/mock_admin_service.go -package=mocks github.com/bete7512/goauth/internal/modules/admin/services AdminService

import (
	"context"
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type AdminService interface {
	ListUsers(ctx context.Context, opts models.UserListOpts) ([]*models.User, int64, *types.GoAuthError)
	GetUser(ctx context.Context, userID string) (*models.User, *types.GoAuthError)
	UpdateUser(ctx context.Context, user *models.User) *types.GoAuthError
	DeleteUser(ctx context.Context, userID string) *types.GoAuthError
}

type adminService struct {
	deps           config.ModuleDependencies
	userRepository models.UserRepository
}

func NewAdminService(
	deps config.ModuleDependencies,
	userRepo models.UserRepository,
) *adminService {
	return &adminService{
		deps:           deps,
		userRepository: userRepo,
	}
}

// ListUsers lists all users with pagination
func (s *adminService) ListUsers(ctx context.Context, opts models.UserListOpts) ([]*models.User, int64, *types.GoAuthError) {
	users, total, err := s.userRepository.List(ctx, opts)
	if err != nil {
		return nil, 0, types.NewInternalError("failed to list users").Wrap(err)
	}
	return users, total, nil
}

// GetUser retrieves a user by ID
func (s *adminService) GetUser(ctx context.Context, userID string) (*models.User, *types.GoAuthError) {
	user, err := s.userRepository.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		return nil, types.NewInternalError("failed to get user").Wrap(err)
	}
	return user, nil
}

// UpdateUser updates a user's information
func (s *adminService) UpdateUser(ctx context.Context, user *models.User) *types.GoAuthError {
	adminUser, ok := ctx.Value(types.UserKey).(*models.User)
	if !ok || adminUser == nil {
		return types.NewUnauthorizedError()
	}

	if err := s.userRepository.Update(ctx, user); err != nil {
		return types.NewInternalError("failed to update user").Wrap(err)
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
func (s *adminService) DeleteUser(ctx context.Context, userID string) *types.GoAuthError {
	// Get admin user for actor_id
	adminUser, ok := ctx.Value(types.UserKey).(*models.User)
	if !ok || adminUser == nil {
		return types.NewUnauthorizedError()
	}

	// Get user info before deletion for logging
	user, err := s.userRepository.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewUserNotFoundError()
		}
		return types.NewInternalError("failed to find user").Wrap(err)
	}

	if err := s.userRepository.Delete(ctx, userID); err != nil {
		return types.NewInternalError("failed to delete user").Wrap(err)
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
func (s *adminService) emitAuditEvent(ctx context.Context, eventType types.EventType, actorID, targetID, targetEmail, details string) {
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
