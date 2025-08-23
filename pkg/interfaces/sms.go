package interfaces

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
)

type SMSSenderInterface interface {
	SendVerificationSMS(ctx context.Context, user models.User, code string) error
	SendWelcomeSMS(ctx context.Context, user models.User) error
	SendForgetPasswordSMS(ctx context.Context, user models.User, code string) error
	SendTwoFactorSMS(ctx context.Context, user models.User, code string) error
	SendMagicLoginOTPSMS(ctx context.Context, user models.User, code string) error
}
