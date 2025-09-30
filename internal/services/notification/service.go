package notification_service

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/interfaces"
)

type NotificationService struct {
	emailSender interfaces.EmailSenderInterface
	smsSender   interfaces.SMSSenderInterface
	tokenRepo   interfaces.TokenRepository
	tokenMgr    interfaces.TokenManagerInterface
	logger      interfaces.Logger
	config      *config.Auth
}

var _ interfaces.NotificationService = (*NotificationService)(nil)

func NewNotificationService(
	emailSender interfaces.EmailSenderInterface,
	smsSender interfaces.SMSSenderInterface,
	tokenRepo interfaces.TokenRepository,
	tokenMgr interfaces.TokenManagerInterface,
	logger interfaces.Logger,
	config *config.Auth,
) *NotificationService {

	return &NotificationService{
		emailSender: emailSender,
		smsSender:   smsSender,
		tokenRepo:   tokenRepo,
		tokenMgr:    tokenMgr,
		logger:      logger,
		config:      config,
	}
}
