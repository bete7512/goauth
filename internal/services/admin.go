package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
)

// ListUsers retrieves a list of users with pagination and filtering
func (s *AuthService) ListUsers(ctx context.Context, req *dto.ListUsersRequest) (*dto.ListUsersResponse, error) {
	filter := interfaces.Filter{
		Pagination: interfaces.Pagination{
			Page:  req.Page,
			Limit: req.Limit,
		},
		Sort: interfaces.Sort{
			Field:     req.SortBy,
			Direction: req.SortDir,
		},
		Search: req.Search,
	}

	users, total, err := s.Auth.Repository.GetUserRepository().GetAllUsers(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	userDTOs := make([]dto.AdminUserData, len(users))
	for i, user := range users {
		userDTOs[i] = s.mapUserToAdminDTO(user)
	}

	totalPages := (int(total) + req.Limit - 1) / req.Limit

	return &dto.ListUsersResponse{
		Users: userDTOs,
		Pagination: dto.Pagination{
			Page:       req.Page,
			Limit:      req.Limit,
			Total:      int(total),
			TotalPages: totalPages,
		},
	}, nil
}

// GetUser retrieves a user by ID for admin purposes
func (s *AuthService) GetUser(ctx context.Context, userID string) (*dto.AdminUserResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	return &dto.AdminUserResponse{
		Message: "user retrieved successfully",
		User:    s.mapUserToAdminDTO(user),
	}, nil
}

// UpdateUser updates a user for admin purposes
func (s *AuthService) UpdateUser(ctx context.Context, userID string, req *dto.AdminUpdateUserRequest) (*dto.AdminUserResponse, error) {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Update fields if provided
	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.PhoneNumber != nil {
		user.PhoneNumber = req.PhoneNumber
	}
	if req.EmailVerified != nil {
		user.EmailVerified = req.EmailVerified
	}
	if req.PhoneVerified != nil {
		user.PhoneVerified = req.PhoneVerified
	}
	if req.TwoFactorEnabled != nil {
		user.TwoFactorEnabled = req.TwoFactorEnabled
	}
	if req.Active != nil {
		user.Active = req.Active
	}
	if req.IsAdmin != nil {
		user.IsAdmin = req.IsAdmin
	}

	user.UpdatedAt = time.Now()

	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &dto.AdminUserResponse{
		Message: "user updated successfully",
		User:    s.mapUserToAdminDTO(user),
	}, nil
}

// DeleteUser deletes a user
func (s *AuthService) DeleteUser(ctx context.Context, userID string) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	if err := s.Auth.Repository.GetUserRepository().DeleteUser(ctx, user); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// ActivateUser activates a user account
func (s *AuthService) ActivateUser(ctx context.Context, userID string) error {
	user, err := s.Auth.Repository.GetUserRepository().GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	active := true
	user.Active = &active
	user.UpdatedAt = time.Now()

	if err := s.Auth.Repository.GetUserRepository().UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to activate user: %w", err)
	}

	return nil
}

// BulkAction performs bulk operations on users
func (s *AuthService) BulkAction(ctx context.Context, req *dto.BulkActionRequest) (*dto.BulkActionResponse, error) {
	// TODO: Implement bulk actions
	// This would require implementing bulk operations in the repository

	return &dto.BulkActionResponse{
		Message:      "bulk action completed",
		SuccessCount: 0,
		FailedCount:  0,
	}, errors.New("not implemented")
}

// GetSystemStats retrieves system statistics
func (s *AuthService) GetSystemStats(ctx context.Context) (*dto.SystemStatsResponse, error) {
	// TODO: Implement system stats
	// This would require implementing stats collection

	return &dto.SystemStatsResponse{
		TotalUsers:          0,
		ActiveUsers:         0,
		InactiveUsers:       0,
		AdminUsers:          0,
		VerifiedUsers:       0,
		UnverifiedUsers:     0,
		TwoFactorUsers:      0,
		RecentRegistrations: 0,
		RecentLogins:        0,
	}, errors.New("not implemented")
}

// GetAuditLogs retrieves audit logs
func (s *AuthService) GetAuditLogs(ctx context.Context, req *dto.AuditLogsRequest) (*dto.AuditLogsResponse, error) {
	// filter := interfaces.Filter{
	// 	Pagination: interfaces.Pagination{
	// 		Page:  req.Page,
	// 		Limit: req.Limit,
	// 	},
	// 	Sort: interfaces.Sort{
	// 		Field:     req.Sort,
	// 		Direction: req.Order,
	// 	},
	// 	Search: req.SearchTerm,
	// 	UserId: req.UserID,
	// }

	// logs, total, err := s.Auth.Repository.GetAuditLogRepository().GetAuditLogs(ctx, filter)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get audit logs: %w", err)
	// }

	// logDTOs := make([]dto.AuditLogData, len(logs))
	// for i, log := range logs {
	// 	logDTOs[i] = dto.AuditLogData{
	// 		ID:        log.ID,
	// 		UserID:    log.UserID,
	// 		EventType: log.EventType,
	// 		Details:   log.Details,
	// 		IP:        log.IP,
	// 		CreatedAt: log.CreatedAt,
	// 	}
	// }

	// totalPages := (int(total) + req.Limit - 1) / req.Limit

	// return &dto.AuditLogsResponse{
	// 	Logs: logDTOs,
	// 	Pagination: dto.Pagination{
	// 		Page:       req.Page,
	// 		Limit:      req.Limit,
	// 		Total:      int(total),
	// 		TotalPages: totalPages,
	// 	},
	// }, nil
	return nil, errors.New("not implemented")
}

// GetSystemHealth retrieves system health information
func (s *AuthService) GetSystemHealth(ctx context.Context) (*dto.SystemHealthResponse, error) {
	// TODO: Implement system health checks
	// This would require implementing health checks for various components

	return &dto.SystemHealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Services:  make(map[string]dto.ServiceHealth),
	}, errors.New("not implemented")
}

// ExportUsers exports user data
func (s *AuthService) ExportUsers(ctx context.Context, req *dto.ExportUsersRequest) (*dto.ExportUsersResponse, error) {
	// TODO: Implement user export
	// This would require implementing export functionality

	return &dto.ExportUsersResponse{
		Message: "user export completed",
		Data:    []dto.AdminUserData{},
	}, errors.New("not implemented")
}

// InviteUser sends an invitation to a new user
func (s *AuthService) InviteUser(ctx context.Context, adminUserID string, req *dto.InviteUserRequest) (*dto.InviteUserResponse, error) {
	// Check if user already exists
	existingUser, err := s.Auth.Repository.GetUserRepository().GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	// Generate invitation token
	invitationToken, err := s.Auth.TokenManager.GenerateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate invitation token: %w", err)
	}

	hashedToken, err := s.Auth.TokenManager.HashToken(invitationToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash invitation token: %w", err)
	}

	// Save invitation token (7 days expiry)
	expiry := 7 * 24 * time.Hour
	if err := s.Auth.Repository.GetTokenRepository().SaveToken(ctx, req.Email, hashedToken, models.InvitationToken, expiry); err != nil {
		return nil, fmt.Errorf("failed to save invitation token: %w", err)
	}

	// Create invitation URL
	invitationURL := fmt.Sprintf("%s/register/invitation?token=%s", s.Auth.Config.App.FrontendURL, invitationToken)

	// Send invitation email
	if s.Auth.Config.Email.CustomSender != nil {
		if err := s.Auth.Config.Email.CustomSender.SendInvitationEmail(ctx, *existingUser, invitationURL); err != nil {
			return nil, fmt.Errorf("failed to send invitation email: %w", err)
		}
	}

	return &dto.InviteUserResponse{
		Message: "invitation sent successfully",
		Email:   req.Email,
	}, nil
}

// ListInvitations retrieves a list of invitations
func (s *AuthService) ListInvitations(ctx context.Context, req *dto.ListInvitationsRequest) (*dto.ListInvitationsResponse, error) {
	// TODO: Implement invitation listing
	// This would require implementing invitation repository

	return &dto.ListInvitationsResponse{
		Invitations: []dto.InvitationData{},
		Pagination: dto.Pagination{
			Page:       req.Page,
			Limit:      req.Limit,
			Total:      0,
			TotalPages: 0,
		},
	}, errors.New("not implemented")
}

// CancelInvitation cancels an invitation
func (s *AuthService) CancelInvitation(ctx context.Context, invitationID string) error {
	// TODO: Implement invitation cancellation
	// This would require implementing invitation repository

	return errors.New("not implemented")
}

// mapUserToAdminDTO maps a user model to admin DTO
func (s *AuthService) mapUserToAdminDTO(user *models.User) dto.AdminUserData {
	return dto.AdminUserData{
		ID:               user.ID,
		Email:            user.Email,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		PhoneNumber:      user.PhoneNumber,
		EmailVerified:    user.EmailVerified,
		PhoneVerified:    user.PhoneVerified,
		TwoFactorEnabled: user.TwoFactorEnabled,
		Active:           user.Active,
		IsAdmin:          user.IsAdmin,
		SignedUpVia:      user.SignedUpVia,
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
		LastLoginAt:      user.LastLoginAt,
	}
}
