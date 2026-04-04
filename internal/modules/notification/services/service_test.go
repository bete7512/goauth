package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	notifmodels "github.com/bete7512/goauth/internal/modules/notification/models"
	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type NotificationServiceSuite struct {
	suite.Suite
}

func TestNotificationServiceSuite(t *testing.T) {
	suite.Run(t, new(NotificationServiceSuite))
}

func (s *NotificationServiceSuite) setup() (
	services.NotificationService,
	*mocks.MockEmailSender,
	*mocks.MockSMSSender,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockEmail := mocks.NewMockEmailSender(ctrl)
	mockSMS := mocks.NewMockSMSSender(ctrl)

	svc := services.NewNotificationService(mockEmail, mockSMS, nil)
	return svc, mockEmail, mockSMS
}

func (s *NotificationServiceSuite) setupNilSenders() services.NotificationService {
	return services.NewNotificationService(nil, nil, nil)
}

// --- SendEmailVerification ---

func (s *NotificationServiceSuite) TestSendEmailVerification_Success() {
	svc, mockEmail, _ := s.setup()
	mockEmail.EXPECT().SendEmail(gomock.Any(), gomock.AssignableToTypeOf(&notifmodels.EmailMessage{})).
		DoAndReturn(func(_ context.Context, msg *notifmodels.EmailMessage) error {
			s.Contains(msg.To, "user@example.com")
			s.NotEmpty(msg.Subject)
			return nil
		})

	err := svc.SendEmailVerification(context.Background(), "user@example.com", "Alice", "https://example.com/verify?token=abc")
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendEmailVerification_NilSender() {
	svc := s.setupNilSenders()
	err := svc.SendEmailVerification(context.Background(), "user@example.com", "Alice", "https://example.com/verify")
	s.NoError(err) // no-op when sender is nil
}

func (s *NotificationServiceSuite) TestSendEmailVerification_SenderError() {
	svc, mockEmail, _ := s.setup()
	mockEmail.EXPECT().SendEmail(gomock.Any(), gomock.Any()).Return(errors.New("SMTP down"))

	err := svc.SendEmailVerification(context.Background(), "user@example.com", "Alice", "https://example.com/verify")
	s.Error(err)
	s.Contains(err.Error(), "SMTP down")
}

// --- SendPhoneVerification ---

func (s *NotificationServiceSuite) TestSendPhoneVerification_Success() {
	svc, _, mockSMS := s.setup()
	mockSMS.EXPECT().SendSMS(gomock.Any(), gomock.AssignableToTypeOf(&notifmodels.SMSMessage{})).
		DoAndReturn(func(_ context.Context, msg *notifmodels.SMSMessage) error {
			s.Equal("+1234567890", msg.To)
			s.NotEmpty(msg.Body)
			return nil
		})

	err := svc.SendPhoneVerification(context.Background(), "+1234567890", "Alice", "123456", "15 minutes")
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendPhoneVerification_NilSender() {
	svc := s.setupNilSenders()
	err := svc.SendPhoneVerification(context.Background(), "+1234567890", "Alice", "123456", "15 minutes")
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendPhoneVerification_SenderError() {
	svc, _, mockSMS := s.setup()
	mockSMS.EXPECT().SendSMS(gomock.Any(), gomock.Any()).Return(errors.New("SMS gateway error"))

	err := svc.SendPhoneVerification(context.Background(), "+1234567890", "Alice", "123456", "15 minutes")
	s.Error(err)
}

// --- SendPasswordResetEmail ---

func (s *NotificationServiceSuite) TestSendPasswordResetEmail_Success() {
	svc, mockEmail, _ := s.setup()
	mockEmail.EXPECT().SendEmail(gomock.Any(), gomock.AssignableToTypeOf(&notifmodels.EmailMessage{})).Return(nil)

	err := svc.SendPasswordResetEmail(context.Background(), "user@example.com", "Alice", "https://example.com/reset", "123456", "1 hour")
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendPasswordResetEmail_NilSender() {
	svc := s.setupNilSenders()
	err := svc.SendPasswordResetEmail(context.Background(), "user@example.com", "Alice", "link", "code", "1h")
	s.NoError(err)
}

// --- SendPasswordResetSMS ---

func (s *NotificationServiceSuite) TestSendPasswordResetSMS_Success() {
	svc, _, mockSMS := s.setup()
	mockSMS.EXPECT().SendSMS(gomock.Any(), gomock.AssignableToTypeOf(&notifmodels.SMSMessage{})).Return(nil)

	err := svc.SendPasswordResetSMS(context.Background(), "+1234567890", "654321", "1 hour")
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendPasswordResetSMS_NilSender() {
	svc := s.setupNilSenders()
	err := svc.SendPasswordResetSMS(context.Background(), "+1234567890", "654321", "1 hour")
	s.NoError(err)
}

// --- SendWelcomeEmail ---

func (s *NotificationServiceSuite) TestSendWelcomeEmail_Success() {
	svc, mockEmail, _ := s.setup()
	mockEmail.EXPECT().SendEmail(gomock.Any(), gomock.AssignableToTypeOf(&notifmodels.EmailMessage{})).Return(nil)

	user := models.User{Email: "user@example.com", Username: "alice"}
	err := svc.SendWelcomeEmail(context.Background(), user)
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendWelcomeEmail_NilSender() {
	svc := s.setupNilSenders()
	user := models.User{Email: "user@example.com", Username: "alice"}
	err := svc.SendWelcomeEmail(context.Background(), user)
	s.NoError(err)
}

// --- SendLoginAlert ---

func (s *NotificationServiceSuite) TestSendLoginAlert_Success() {
	svc, mockEmail, _ := s.setup()
	mockEmail.EXPECT().SendEmail(gomock.Any(), gomock.AssignableToTypeOf(&notifmodels.EmailMessage{})).Return(nil)

	user := models.User{Email: "user@example.com", Username: "alice"}
	metadata := map[string]interface{}{
		"ip_address": "192.168.1.1",
		"timestamp":  "2024-01-01 12:00:00",
	}
	err := svc.SendLoginAlert(context.Background(), user, metadata)
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendLoginAlert_NilSender() {
	svc := s.setupNilSenders()
	user := models.User{Email: "user@example.com"}
	err := svc.SendLoginAlert(context.Background(), user, nil)
	s.NoError(err)
}

// --- SendPasswordChangedAlert ---

func (s *NotificationServiceSuite) TestSendPasswordChangedAlert_Success() {
	svc, mockEmail, _ := s.setup()
	mockEmail.EXPECT().SendEmail(gomock.Any(), gomock.AssignableToTypeOf(&notifmodels.EmailMessage{})).Return(nil)

	user := models.User{Email: "user@example.com", Username: "alice"}
	err := svc.SendPasswordChangedAlert(context.Background(), user)
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendPasswordChangedAlert_NilSender() {
	svc := s.setupNilSenders()
	user := models.User{Email: "user@example.com"}
	err := svc.SendPasswordChangedAlert(context.Background(), user)
	s.NoError(err)
}

// --- SendMagicLinkEmail ---

func (s *NotificationServiceSuite) TestSendMagicLinkEmail_Success() {
	svc, mockEmail, _ := s.setup()
	mockEmail.EXPECT().SendEmail(gomock.Any(), gomock.AssignableToTypeOf(&notifmodels.EmailMessage{})).Return(nil)

	err := svc.SendMagicLinkEmail(context.Background(), "user@example.com", "Alice", "https://example.com/magic?token=abc", "123456", "15 minutes")
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendMagicLinkEmail_NilSender() {
	svc := s.setupNilSenders()
	err := svc.SendMagicLinkEmail(context.Background(), "user@example.com", "Alice", "link", "code", "15m")
	s.NoError(err)
}

// --- SendCustomEmail ---

func (s *NotificationServiceSuite) TestSendCustomEmail_Success() {
	svc, mockEmail, _ := s.setup()
	msg := &notifmodels.EmailMessage{
		To:       []string{"user@example.com"},
		Subject:  "Custom",
		TextBody: "Hello",
	}
	mockEmail.EXPECT().SendEmail(gomock.Any(), msg).Return(nil)

	err := svc.SendCustomEmail(context.Background(), msg)
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendCustomEmail_NilSender() {
	svc := s.setupNilSenders()
	msg := &notifmodels.EmailMessage{To: []string{"user@example.com"}}
	err := svc.SendCustomEmail(context.Background(), msg)
	s.Error(err)
	s.Contains(err.Error(), "email sender not configured")
}

func (s *NotificationServiceSuite) TestSendCustomEmail_SenderError() {
	svc, mockEmail, _ := s.setup()
	mockEmail.EXPECT().SendEmail(gomock.Any(), gomock.Any()).Return(errors.New("send failed"))

	err := svc.SendCustomEmail(context.Background(), &notifmodels.EmailMessage{})
	s.Error(err)
}

// --- SendCustomSMS ---

func (s *NotificationServiceSuite) TestSendCustomSMS_Success() {
	svc, _, mockSMS := s.setup()
	msg := &notifmodels.SMSMessage{To: "+1234567890", Body: "Hello"}
	mockSMS.EXPECT().SendSMS(gomock.Any(), msg).Return(nil)

	err := svc.SendCustomSMS(context.Background(), msg)
	s.NoError(err)
}

func (s *NotificationServiceSuite) TestSendCustomSMS_NilSender() {
	svc := s.setupNilSenders()
	msg := &notifmodels.SMSMessage{To: "+1234567890"}
	err := svc.SendCustomSMS(context.Background(), msg)
	s.Error(err)
	s.Contains(err.Error(), "SMS sender not configured")
}

func (s *NotificationServiceSuite) TestSendCustomSMS_SenderError() {
	svc, _, mockSMS := s.setup()
	mockSMS.EXPECT().SendSMS(gomock.Any(), gomock.Any()).Return(errors.New("gateway down"))

	err := svc.SendCustomSMS(context.Background(), &notifmodels.SMSMessage{})
	s.Error(err)
}
