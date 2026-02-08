package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/admin/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type AdminServiceSuite struct {
	suite.Suite
}

func TestAdminServiceSuite(t *testing.T) {
	suite.Run(t, new(AdminServiceSuite))
}

func (s *AdminServiceSuite) setupService() (
	services.AdminService,
	*mocks.MockUserRepository,
	*mocks.MockEventBus,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockEvents := mocks.NewMockEventBus(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(),
		Events: mockEvents,
		Logger: mockLogger,
	}

	svc := services.NewAdminService(deps, mockUserRepo)
	return svc, mockUserRepo, mockEvents
}

// ---------------------------------------------------------------------------
// ListUsers
// ---------------------------------------------------------------------------

func (s *AdminServiceSuite) TestListUsers() {
	user1 := testutil.TestUser()
	user2 := testutil.TestUser()
	user2.Email = "other@example.com"

	tests := []struct {
		name      string
		setup     func(*mocks.MockUserRepository)
		wantCount int
		wantTotal int64
		wantErr   bool
	}{
		{
			name: "success with results",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().List(gomock.Any(), gomock.Any()).Return([]*models.User{user1, user2}, int64(2), nil)
			},
			wantCount: 2,
			wantTotal: 2,
		},
		{
			name: "success with empty list",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().List(gomock.Any(), gomock.Any()).Return([]*models.User{}, int64(0), nil)
			},
			wantCount: 0,
			wantTotal: 0,
		},
		{
			name: "repository error",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, _ := s.setupService()
			tt.setup(mockUserRepo)

			users, total, authErr := svc.ListUsers(context.Background(), models.UserListOpts{})

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(users)
			} else {
				s.Nil(authErr)
				s.Len(users, tt.wantCount)
				s.Equal(tt.wantTotal, total)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func (s *AdminServiceSuite) TestGetUser() {
	user := testutil.TestUser()

	tests := []struct {
		name    string
		userID  string
		setup   func(*mocks.MockUserRepository)
		wantErr bool
	}{
		{
			name:   "success",
			userID: user.ID,
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
			},
		},
		{
			name:   "user not found",
			userID: "nonexistent",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().FindByID(gomock.Any(), "nonexistent").Return(nil, errors.New("not found"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, _ := s.setupService()
			tt.setup(mockUserRepo)

			result, authErr := svc.GetUser(context.Background(), tt.userID)

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(result)
			} else {
				s.Nil(authErr)
				s.NotNil(result)
				s.Equal(user.ID, result.ID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateUser
// ---------------------------------------------------------------------------

func (s *AdminServiceSuite) TestUpdateUser() {
	adminUser := testutil.TestAdminUser()
	targetUser := testutil.TestUser()
	targetUser.Email = "target@example.com"

	tests := []struct {
		name    string
		ctx     context.Context
		setup   func(*mocks.MockUserRepository, *mocks.MockEventBus)
		wantErr bool
	}{
		{
			name: "success",
			ctx:  testutil.ContextWithAdminUser(context.Background(), adminUser),
			setup: func(ur *mocks.MockUserRepository, ev *mocks.MockEventBus) {
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventAdminUserUpdated, gomock.Any()).Return(nil)
			},
		},
		{
			name: "admin user not in context",
			ctx:  context.Background(),
			setup: func(ur *mocks.MockUserRepository, ev *mocks.MockEventBus) {
				// No calls expected
			},
			wantErr: true,
		},
		{
			name: "repository error",
			ctx:  testutil.ContextWithAdminUser(context.Background(), adminUser),
			setup: func(ur *mocks.MockUserRepository, ev *mocks.MockEventBus) {
				ur.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, mockEvents := s.setupService()
			tt.setup(mockUserRepo, mockEvents)

			authErr := svc.UpdateUser(tt.ctx, targetUser)

			if tt.wantErr {
				s.NotNil(authErr)
			} else {
				s.Nil(authErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DeleteUser
// ---------------------------------------------------------------------------

func (s *AdminServiceSuite) TestDeleteUser() {
	adminUser := testutil.TestAdminUser()
	targetUser := testutil.TestUser()
	targetUser.Email = "target@example.com"

	tests := []struct {
		name    string
		ctx     context.Context
		userID  string
		setup   func(*mocks.MockUserRepository, *mocks.MockEventBus)
		wantErr bool
	}{
		{
			name:   "success",
			ctx:    testutil.ContextWithAdminUser(context.Background(), adminUser),
			userID: targetUser.ID,
			setup: func(ur *mocks.MockUserRepository, ev *mocks.MockEventBus) {
				ur.EXPECT().FindByID(gomock.Any(), targetUser.ID).Return(targetUser, nil)
				ur.EXPECT().Delete(gomock.Any(), targetUser.ID).Return(nil)
				ev.EXPECT().EmitAsync(gomock.Any(), types.EventAdminUserDeleted, gomock.Any()).Return(nil)
			},
		},
		{
			name:   "admin user not in context",
			ctx:    context.Background(),
			userID: targetUser.ID,
			setup: func(ur *mocks.MockUserRepository, ev *mocks.MockEventBus) {
				// No calls expected
			},
			wantErr: true,
		},
		{
			name:   "user not found before deletion",
			ctx:    testutil.ContextWithAdminUser(context.Background(), adminUser),
			userID: "nonexistent",
			setup: func(ur *mocks.MockUserRepository, ev *mocks.MockEventBus) {
				ur.EXPECT().FindByID(gomock.Any(), "nonexistent").Return(nil, errors.New("not found"))
			},
			wantErr: true,
		},
		{
			name:   "repository delete error",
			ctx:    testutil.ContextWithAdminUser(context.Background(), adminUser),
			userID: targetUser.ID,
			setup: func(ur *mocks.MockUserRepository, ev *mocks.MockEventBus) {
				ur.EXPECT().FindByID(gomock.Any(), targetUser.ID).Return(targetUser, nil)
				ur.EXPECT().Delete(gomock.Any(), targetUser.ID).Return(errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, mockEvents := s.setupService()
			tt.setup(mockUserRepo, mockEvents)

			authErr := svc.DeleteUser(tt.ctx, tt.userID)

			if tt.wantErr {
				s.NotNil(authErr)
			} else {
				s.Nil(authErr)
			}
		})
	}
}
