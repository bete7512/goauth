package handlers

import (
	"github.com/bete7512/goauth/internal/modules/notification/services"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
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
			Name:    string(types.RouteNotificationSendVerificationEmail),
			Path:    "/send-verification-email",
			Method:  "POST",
			Handler: h.SendVerificationEmail,
		},
		{
			Name:    string(types.RouteNotificationResendVerificationEmail),
			Path:    "/resend-verification-email",
			Method:  "POST",
			Handler: h.ResendVerificationEmail,
		},

		// 📌 Phone Verification
		{
			Name:    string(types.RouteNotificationSendVerificationPhone),
			Path:    "/send-verification-phone",
			Method:  "POST",
			Handler: h.SendVerificationPhone,
		},
		{
			Name:    string(types.RouteNotificationResendVerificationPhone),
			Path:    "/resend-verification-phone",
			Method:  "POST",
			Handler: h.ResendVerificationPhone,
		},

		// 📌 Password Recovery
		{
			Name:    string(types.RouteNotificationForgotPassword),
			Path:    "/forgot-password",
			Method:  "POST",
			Handler: h.ForgotPassword,
		},

		// 📌 Verification Processing
		{
			Name:    string(types.RouteNotificationVerifyEmail),
			Path:    "/verify-email",
			Method:  "GET",
			Handler: h.VerifyEmail,
		},
		{
			Name:    string(types.RouteNotificationVerifyPhone),
			Path:    "/verify-phone",
			Method:  "POST",
			Handler: h.VerifyPhone,
		},
	}
	return routes
}
