package handlers

import (
	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/pkg/config"
)

type NotificationHandler struct {
	NotificationService *services.NotificationService
	deps                config.ModuleDependencies
}

func NewNotificationHandler(notificationService *services.NotificationService, deps config.ModuleDependencies) *NotificationHandler {
	return &NotificationHandler{
		NotificationService: notificationService,
		deps:                deps,
	}
}

func (h *NotificationHandler) GetRoutes() []config.RouteInfo {
	routes := []config.RouteInfo{
		// 📌 Email Verification
		{
			Name:    "notification.send_verification_email",
			Path:    "/send-verification-email",
			Method:  "POST",
			Handler: h.SendVerificationEmail,
		},
		{
			Name:    "notification.resend_verification_email",
			Path:    "/resend-verification-email",
			Method:  "POST",
			Handler: h.ResendVerificationEmail,
		},

		// 📌 Phone Verification
		{
			Name:    "notification.send_verification_phone",
			Path:    "/send-verification-phone",
			Method:  "POST",
			Handler: h.SendVerificationPhone,
		},
		{
			Name:    "notification.resend_verification_phone",
			Path:    "/resend-verification-phone",
			Method:  "POST",
			Handler: h.ResendVerificationPhone,
		},

		// 📌 Password Recovery
		{
			Name:    "notification.forgot_password",
			Path:    "/forgot-password",
			Method:  "POST",
			Handler: h.ForgotPassword,
		},

		// 📌 Verification Processing
		{
			Name:    "notification.verify_email",
			Path:    "/verify-email",
			Method:  "POST",
			Handler: h.VerifyEmail,
		},
		{
			Name:    "notification.verify_phone",
			Path:    "/verify-phone",
			Method:  "POST",
			Handler: h.VerifyPhone,
		},
	}
	return routes
}
