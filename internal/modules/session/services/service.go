package services

//go:generate mockgen -destination=../../../mocks/mock_session_service.go -package=mocks github.com/bete7512/goauth/internal/modules/session/services SessionService

import (
	"context"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/internal/utils/logger"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type SessionService interface {
	Login(ctx context.Context, req *dto.LoginRequest, metadata *types.RequestMetadata) (dto.AuthResponse, *types.GoAuthError)
	Logout(ctx context.Context, userID, sessionID string) *types.GoAuthError
	Refresh(ctx context.Context, req *dto.RefreshRequest) (dto.AuthResponse, *types.GoAuthError)
	ListSessions(ctx context.Context, userID, currentSessionID string, opts models.SessionListOpts) ([]dto.SessionDTO, int64, *types.GoAuthError)
	GetSession(ctx context.Context, userID, sessionID string) (*dto.SessionDTO, *types.GoAuthError)
	DeleteSession(ctx context.Context, userID, sessionID string) *types.GoAuthError
	DeleteAllSessions(ctx context.Context, userID string) *types.GoAuthError
	FindSessionByToken(ctx context.Context, token string) (*models.Session, *types.GoAuthError)
}

type sessionService struct {
	deps              config.ModuleDependencies
	config            *config.SessionModuleConfig
	userRepository    models.UserRepository
	sessionRepository models.SessionRepository
	logger            logger.Logger
	securityManager   *security.SecurityManager
}

func NewSessionService(
	deps config.ModuleDependencies,
	userRepository models.UserRepository,
	sessionRepository models.SessionRepository,
	logger logger.Logger,
	securityManager *security.SecurityManager,
	cfg *config.SessionModuleConfig,
) *sessionService {
	return &sessionService{
		deps:              deps,
		userRepository:    userRepository,
		sessionRepository: sessionRepository,
		logger:            logger,
		securityManager:   securityManager,
		config:            cfg,
	}
}
