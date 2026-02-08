package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/audit/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type AuditServiceSuite struct {
	suite.Suite
}

func TestAuditServiceSuite(t *testing.T) {
	suite.Run(t, new(AuditServiceSuite))
}

func (s *AuditServiceSuite) setupService(retentionDays map[string]int) (
	services.AuditService,
	*mocks.MockAuditLogRepository,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockAuditRepo := mocks.NewMockAuditLogRepository(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	deps := config.ModuleDependencies{
		Config: testutil.TestConfig(),
		Logger: mockLogger,
	}

	svc := services.NewAuditService(deps, mockAuditRepo, retentionDays)
	return svc, mockAuditRepo
}

func testAuditLog(id, action, actorID string) *models.AuditLog {
	return &models.AuditLog{
		ID:        id,
		Action:    action,
		ActorID:   actorID,
		ActorType: "user",
		Severity:  "info",
		Details:   "test action",
		CreatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// CreateAuditLog
// ---------------------------------------------------------------------------

func (s *AuditServiceSuite) TestCreateAuditLog() {
	tests := []struct {
		name    string
		setup   func(*mocks.MockAuditLogRepository)
		wantErr bool
	}{
		{
			name: "success",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
			},
		},
		{
			name: "repository error",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockRepo := s.setupService(nil)
			tt.setup(mockRepo)

			log := testAuditLog("log-1", "auth.login.success", "user-1")
			authErr := svc.CreateAuditLog(context.Background(), log)

			if tt.wantErr {
				s.NotNil(authErr)
			} else {
				s.Nil(authErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetMyAuditLogs
// ---------------------------------------------------------------------------

func (s *AuditServiceSuite) TestGetMyAuditLogs() {
	userID := "user-1"
	actorLog := testAuditLog("log-1", "auth.login.success", userID)
	targetLog := testAuditLog("log-2", "admin.user.updated", "admin-1")

	tests := []struct {
		name      string
		setup     func(*mocks.MockAuditLogRepository)
		wantCount int
		wantErr   bool
	}{
		{
			name: "success merges actor and target logs",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return([]*models.AuditLog{actorLog}, int64(1), nil)
				r.EXPECT().FindByTargetID(gomock.Any(), userID, gomock.Any()).Return([]*models.AuditLog{targetLog}, int64(1), nil)
			},
			wantCount: 2,
		},
		{
			name: "deduplicates logs",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return([]*models.AuditLog{actorLog}, int64(1), nil)
				r.EXPECT().FindByTargetID(gomock.Any(), userID, gomock.Any()).Return([]*models.AuditLog{actorLog}, int64(1), nil) // same log
			},
			wantCount: 1,
		},
		{
			name: "actor logs error",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
		},
		{
			name: "target logs error",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return([]*models.AuditLog{}, int64(0), nil)
				r.EXPECT().FindByTargetID(gomock.Any(), userID, gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockRepo := s.setupService(nil)
			tt.setup(mockRepo)

			opts := models.AuditLogListOpts{}
			opts.Limit = 20
			logs, _, authErr := svc.GetMyAuditLogs(context.Background(), userID, opts)

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(logs)
			} else {
				s.Nil(authErr)
				s.Len(logs, tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetMyLogins
// ---------------------------------------------------------------------------

func (s *AuditServiceSuite) TestGetMyLogins() {
	userID := "user-1"
	loginLog := testAuditLog("log-1", "auth.login.success", userID)
	profileLog := testAuditLog("log-2", "user.profile.updated", userID)

	tests := []struct {
		name      string
		setup     func(*mocks.MockAuditLogRepository)
		wantCount int
		wantErr   bool
	}{
		{
			name: "filters login events only",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return(
					[]*models.AuditLog{loginLog, profileLog}, int64(2), nil,
				)
			},
			wantCount: 1,
		},
		{
			name: "repository error",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockRepo := s.setupService(nil)
			tt.setup(mockRepo)

			opts := models.AuditLogListOpts{}
			opts.Limit = 20
			logs, _, authErr := svc.GetMyLogins(context.Background(), userID, opts)

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(logs)
			} else {
				s.Nil(authErr)
				s.Len(logs, tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetMyChanges
// ---------------------------------------------------------------------------

func (s *AuditServiceSuite) TestGetMyChanges() {
	userID := "user-1"
	profileLog := testAuditLog("log-1", "user.profile.updated", userID)
	passwordLog := testAuditLog("log-2", "auth.password.changed", userID)
	loginLog := testAuditLog("log-3", "auth.login.success", userID)

	tests := []struct {
		name      string
		setup     func(*mocks.MockAuditLogRepository)
		wantCount int
		wantErr   bool
	}{
		{
			name: "filters change events only",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return(
					[]*models.AuditLog{profileLog, passwordLog, loginLog}, int64(3), nil,
				)
			},
			wantCount: 2, // profileLog + passwordLog, not loginLog
		},
		{
			name: "repository error",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockRepo := s.setupService(nil)
			tt.setup(mockRepo)

			opts := models.AuditLogListOpts{}
			opts.Limit = 20
			logs, _, authErr := svc.GetMyChanges(context.Background(), userID, opts)

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(logs)
			} else {
				s.Nil(authErr)
				s.Len(logs, tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetMySecurity
// ---------------------------------------------------------------------------

func (s *AuditServiceSuite) TestGetMySecurity() {
	userID := "user-1"
	secLog := testAuditLog("log-1", "security.suspicious.login", userID)
	tfaLog := testAuditLog("log-2", "auth.2fa.enabled", userID)
	loginLog := testAuditLog("log-3", "auth.login.success", userID)

	tests := []struct {
		name      string
		setup     func(*mocks.MockAuditLogRepository)
		wantCount int
		wantErr   bool
	}{
		{
			name: "filters security events only",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return(
					[]*models.AuditLog{secLog, tfaLog, loginLog}, int64(3), nil,
				)
			},
			wantCount: 2, // secLog + tfaLog, not loginLog
		},
		{
			name: "repository error",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockRepo := s.setupService(nil)
			tt.setup(mockRepo)

			opts := models.AuditLogListOpts{}
			opts.Limit = 20
			logs, _, authErr := svc.GetMySecurity(context.Background(), userID, opts)

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(logs)
			} else {
				s.Nil(authErr)
				s.Len(logs, tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ListAllAuditLogs (admin)
// ---------------------------------------------------------------------------

func (s *AuditServiceSuite) TestListAllAuditLogs() {
	log1 := testAuditLog("log-1", "auth.login.success", "user-1")
	log2 := testAuditLog("log-2", "admin.user.deleted", "admin-1")

	tests := []struct {
		name      string
		setup     func(*mocks.MockAuditLogRepository)
		wantCount int
		wantTotal int64
		wantErr   bool
	}{
		{
			name: "success",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().List(gomock.Any(), gomock.Any()).Return([]*models.AuditLog{log1, log2}, int64(2), nil)
			},
			wantCount: 2,
			wantTotal: 2,
		},
		{
			name: "empty list",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().List(gomock.Any(), gomock.Any()).Return([]*models.AuditLog{}, int64(0), nil)
			},
			wantCount: 0,
			wantTotal: 0,
		},
		{
			name: "repository error",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockRepo := s.setupService(nil)
			tt.setup(mockRepo)

			logs, total, authErr := svc.ListAllAuditLogs(context.Background(), models.AuditLogListOpts{})

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(logs)
			} else {
				s.Nil(authErr)
				s.Len(logs, tt.wantCount)
				s.Equal(tt.wantTotal, total)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetUserAuditLogs (admin)
// ---------------------------------------------------------------------------

func (s *AuditServiceSuite) TestGetUserAuditLogs() {
	userID := "user-1"
	actorLog := testAuditLog("log-1", "auth.login.success", userID)
	targetLog := testAuditLog("log-2", "admin.user.updated", "admin-1")

	tests := []struct {
		name      string
		setup     func(*mocks.MockAuditLogRepository)
		wantCount int
		wantErr   bool
	}{
		{
			name: "success",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return([]*models.AuditLog{actorLog}, int64(1), nil)
				r.EXPECT().FindByTargetID(gomock.Any(), userID, gomock.Any()).Return([]*models.AuditLog{targetLog}, int64(1), nil)
			},
			wantCount: 2,
		},
		{
			name: "actor logs error",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByActorID(gomock.Any(), userID, gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockRepo := s.setupService(nil)
			tt.setup(mockRepo)

			opts := models.AuditLogListOpts{}
			opts.Limit = 20
			logs, _, authErr := svc.GetUserAuditLogs(context.Background(), userID, opts)

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(logs)
			} else {
				s.Nil(authErr)
				s.Len(logs, tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetAuditLogsByAction (admin)
// ---------------------------------------------------------------------------

func (s *AuditServiceSuite) TestGetAuditLogsByAction() {
	log1 := testAuditLog("log-1", "auth.login.success", "user-1")

	tests := []struct {
		name      string
		action    string
		setup     func(*mocks.MockAuditLogRepository)
		wantCount int
		wantErr   bool
	}{
		{
			name:   "success",
			action: "auth.login.success",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByAction(gomock.Any(), "auth.login.success", gomock.Any()).Return([]*models.AuditLog{log1}, int64(1), nil)
			},
			wantCount: 1,
		},
		{
			name:   "repository error",
			action: "auth.login.success",
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().FindByAction(gomock.Any(), "auth.login.success", gomock.Any()).Return(nil, int64(0), errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockRepo := s.setupService(nil)
			tt.setup(mockRepo)

			logs, _, authErr := svc.GetAuditLogsByAction(context.Background(), tt.action, models.AuditLogListOpts{})

			if tt.wantErr {
				s.NotNil(authErr)
				s.Nil(logs)
			} else {
				s.Nil(authErr)
				s.Len(logs, tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CleanupOldLogs
// ---------------------------------------------------------------------------

func (s *AuditServiceSuite) TestCleanupOldLogs() {
	tests := []struct {
		name          string
		retentionDays map[string]int
		setup         func(*mocks.MockAuditLogRepository)
		wantErr       bool
	}{
		{
			name:          "success",
			retentionDays: map[string]int{"auth.*": 90},
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().DeleteByActionOlderThan(gomock.Any(), "auth.*", gomock.Any()).Return(nil)
			},
		},
		{
			name:          "skips negative retention",
			retentionDays: map[string]int{"security.*": -1},
			setup: func(r *mocks.MockAuditLogRepository) {
				// No calls expected — -1 means keep forever
			},
		},
		{
			name:          "repository error",
			retentionDays: map[string]int{"auth.*": 90},
			setup: func(r *mocks.MockAuditLogRepository) {
				r.EXPECT().DeleteByActionOlderThan(gomock.Any(), "auth.*", gomock.Any()).Return(errors.New("db error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockRepo := s.setupService(tt.retentionDays)
			tt.setup(mockRepo)

			authErr := svc.CleanupOldLogs(context.Background())

			if tt.wantErr {
				s.NotNil(authErr)
			} else {
				s.Nil(authErr)
			}
		})
	}
}
