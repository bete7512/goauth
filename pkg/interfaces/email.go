package interfaces

import (
	"context"

	"github.com/bete7512/goauth/pkg/types"
)

type EmailSenderInterface interface {
	SendVerificationEmail(ctx context.Context, user types.User, redirectURL string) error
	SendWelcomeEmail(ctx context.Context, user types.User) error
	SendPasswordResetEmail(ctx context.Context, user types.User, redirectURL string) error
	SendTwoFactorEmail(ctx context.Context, user types.User, code string) error
	SendMagicLinkEmail(ctx context.Context, user types.User, redirectURL string) error
}
