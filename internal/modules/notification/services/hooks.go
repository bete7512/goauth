package services

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
)

// SendWelcomeEmail sends a welcome email to the user.
func (s *notificationService) SendWelcomeEmail(ctx context.Context, user models.User) error {
	tmpl, ok := s.templates["welcome"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"AppName":  s.config.AppName,
		"UserName": user.Username,
	}

	return s.sendTemplatedEmail(ctx, &tmpl, user.Email, data)
}

// SendLoginAlert sends a login alert email to the user.
func (s *notificationService) SendLoginAlert(ctx context.Context, user models.User, metadata map[string]interface{}) error {
	tmpl, ok := s.templates["login_alert"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"UserName":  user.Username,
		"IPAddress": metadata["ip_address"],
		"Timestamp": metadata["timestamp"],
	}

	return s.sendTemplatedEmail(ctx, &tmpl, user.Email, data)
}

// SendPasswordChangedAlert sends a password changed alert email.
func (s *notificationService) SendPasswordChangedAlert(ctx context.Context, user models.User) error {
	tmpl, ok := s.templates["password_changed"]
	if !ok || !tmpl.Enabled {
		return nil
	}

	data := map[string]interface{}{
		"UserName":    user.Username,
		"Timestamp":   time.Now().Format("2006-01-02 15:04:05"),
		"SupportLink": s.config.SupportLink,
	}

	return s.sendTemplatedEmail(ctx, &tmpl, user.Email, data)
}
