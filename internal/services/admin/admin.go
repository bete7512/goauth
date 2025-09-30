package admin_service

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/dto"
	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// ListUsers retrieves a list of users with pagination and filtering
func (s *AdminService) ListUsers(ctx context.Context, req *dto.SearchRequest) (*dto.ListUsersResponse, *types.GoAuthError) {
	filter := interfaces.Filter{
		Pagination: interfaces.Pagination{
			Page:  req.Page,
			Limit: req.Limit,
		},
		Sort: interfaces.Sort{
			Field:     req.Sort,
			Direction: req.Order,
		},
		Search: req.Search,
	}

	users, total, err := s.userRepo.GetAllUsers(ctx, filter)
	if err != nil {
		return nil, types.NewInternalError(err.Error())
	}

	userDTOs := make([]dto.UserResponse, len(users))
	for i, user := range users {
		userDTOs[i] = dto.UserResponse{
			ID:               user.ID,
			FirstName:        user.FirstName,
			LastName:         user.LastName,
			Email:            user.Email,
			EmailVerified:    user.EmailVerified != nil && *user.EmailVerified,
			PhoneNumber:      user.PhoneNumber,
			PhoneVerified:    user.PhoneVerified != nil && *user.PhoneVerified,
			TwoFactorEnabled: user.TwoFactorEnabled != nil && *user.TwoFactorEnabled,
			Avatar:           user.Avatar,
			CreatedAt:        user.CreatedAt,
			UpdatedAt:        user.UpdatedAt,
			LastLoginAt:      user.LastLoginAt,
		}
	}

	totalPages := (int(total) + req.Limit - 1) / req.Limit
	hasNext := int64(req.Page*req.Limit) < total
	hasPrev := req.Page > 1
	return &dto.ListUsersResponse{
		Users: userDTOs,
		Pagination: dto.PaginationMeta{
			Page:       req.Page,
			Limit:      req.Limit,
			Total:      total,
			TotalPages: totalPages,
			HasNext:    hasNext,
			HasPrev:    hasPrev,
		},
	}, nil
}

// GetUser retrieves a user by ID for admin purposes
func (s *AdminService) GetUser(ctx context.Context, userID string) (*dto.AdminUserResponse, *types.GoAuthError) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
	}

	return &dto.AdminUserResponse{
		Message: "user retrieved successfully",
		User:    s.mapUserToAdminDTO(user),
	}, nil
}

// UpdateUser updates a user for admin purposes
func (s *AdminService) UpdateUser(ctx context.Context, userID string, req *dto.AdminUpdateUserRequest) (*dto.AdminUserResponse, *types.GoAuthError) {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, types.NewUserNotFoundError()
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

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Errorf("failed to update user: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	return &dto.AdminUserResponse{
		Message: "user updated successfully",
		User:    s.mapUserToAdminDTO(user),
	}, nil
}

// DeleteUser deletes a user
func (s *AdminService) DeleteUser(ctx context.Context, userID string) *types.GoAuthError {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return types.NewUserNotFoundError()
	}

	if err := s.userRepo.DeleteUser(ctx, user); err != nil {
		s.logger.Errorf("failed to delete user: %v", err)
		return types.NewInternalError(err.Error())
	}

	return nil
}

// ActivateUser activates a user account
func (s *AdminService) ActivateUser(ctx context.Context, userID string) *types.GoAuthError {
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return types.NewUserNotFoundError()
	}

	active := true
	user.Active = &active
	user.UpdatedAt = time.Now()

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Errorf("failed to activate user: %v", err)
		return types.NewInternalError(err.Error())
	}

	return nil
}

// BulkAction performs bulk operations on users
func (s *AdminService) BulkAction(ctx context.Context, req *dto.BulkActionRequest) (*dto.BulkActionResponse, *types.GoAuthError) {
	// TODO: Implement bulk actions
	// This would require implementing bulk operations in the repository

	return &dto.BulkActionResponse{
		Message:      "bulk action completed",
		SuccessCount: 0,
		FailedCount:  0,
	}, nil
}

// GetSystemStats retrieves system statistics
func (s *AdminService) GetSystemStats(ctx context.Context) (*dto.SystemStatsResponse, *types.GoAuthError) {
	// TODO: Implement system stats
	// This would require implementing stats collection

	return nil, types.NewCustomError("not implemented")
}

// GetAuditLogs retrieves audit logs
func (s *AdminService) GetAuditLogs(ctx context.Context, req *dto.AuditLogsRequest) (*dto.AuditLogsResponse, *types.GoAuthError) {
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
	return nil, types.NewCustomError("not implemented")
}

// GetSystemHealth retrieves system health information
func (s *AdminService) GetSystemHealth(ctx context.Context) (*dto.SystemHealthResponse, *types.GoAuthError) {
	// TODO: Implement system health checks
	// This would require implementing health checks for various components

	return &dto.SystemHealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Services:  make(map[string]dto.ServiceHealth),
	}, types.NewCustomError("not implemented")
}

// ExportUsers exports user data
func (s *AdminService) ExportUsers(ctx context.Context, req *dto.ExportUsersRequest) (*dto.ExportUsersResponse, *types.GoAuthError) {
	// TODO: Implement user export
	// This would require implementing export functionality

	return &dto.ExportUsersResponse{
		Message: "user export completed",
		Data:    []dto.AdminUserData{},
	}, types.NewCustomError("not implemented")
}

// InviteUser sends an invitation to a new user
func (s *AdminService) InviteUser(ctx context.Context, adminUserID string, req *dto.InviteUserRequest) (resp *dto.InviteUserResponse, err *types.GoAuthError) {
	// Check if user already exists
	existingUser, ierr := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, types.NewUserAlreadyExistsError()
	}
	if ierr != nil {
		s.logger.Errorf("failed to get user by email: %v", ierr)
		return nil, types.NewInternalError(ierr.Error())
	}

	// Generate invitation token
	invitationToken, errr := s.tokenMgr.GenerateRandomToken(32)
	if err != nil {
		s.logger.Errorf("failed to generate invitation token: %v", err)
		return nil, types.NewInternalError(errr.Error())
	}

	hashedToken, errr := s.tokenMgr.HashToken(invitationToken)
	if errr != nil {
		s.logger.Errorf("failed to hash invitation token: %v", errr)
		return nil, types.NewInternalError(errr.Error())
	}

	// Save invitation token (7 days expiry)
	expiry := 7 * 24 * time.Hour
	if err := s.tokenRepo.SaveToken(ctx, req.Email, hashedToken, models.InvitationToken, expiry); err != nil {
		s.logger.Errorf("failed to save invitation token: %v", err)
		return nil, types.NewInternalError(err.Error())
	}

	// Create invitation URL
	invitationURL := fmt.Sprintf("%s/register/invitation?token=%s", s.config.Config.App.FrontendURL, invitationToken)

	// Send invitation email
	if s.config.Email.CustomSender != nil {
		if err := s.config.Email.CustomSender.SendInvitationEmail(ctx, *existingUser, invitationURL); err != nil {
			s.logger.Errorf("failed to send invitation email: %v", err)
			return nil, types.NewInternalError(err.Error())
		}
	}

	return &dto.InviteUserResponse{
		Message: "invitation sent successfully",
		Email:   req.Email,
	}, nil
}

// ListInvitations retrieves a list of invitations
func (s *AdminService) ListInvitations(ctx context.Context, req *dto.ListInvitationsRequest) (*dto.ListInvitationsResponse, *types.GoAuthError) {
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
	}, types.NewCustomError("not implemented")
}

// CancelInvitation cancels an invitation
func (s *AdminService) CancelInvitation(ctx context.Context, invitationID string) *types.GoAuthError {
	// TODO: Implement invitation cancellation
	// This would require implementing invitation repository

	return types.NewCustomError("not implemented")
}

// mapUserToAdminDTO maps a user model to admin DTO
func (s *AdminService) mapUserToAdminDTO(user *models.User) dto.AdminUserData {
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
