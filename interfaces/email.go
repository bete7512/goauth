package interfaces

import (
	"context"

	"github.com/bete7512/goauth/models"
)

type EmailSenderInterface interface {
	SendVerificationEmail(ctx context.Context, user models.User, redirectURL string) error
	SendWelcomeEmail(ctx context.Context, user models.User) error
	SendPasswordResetEmail(ctx context.Context, user models.User, redirectURL string) error
	SendTwoFactorEmail(ctx context.Context, user models.User, code string) error
	SendMagicLinkEmail(ctx context.Context, user models.User, redirectURL string) error
}
