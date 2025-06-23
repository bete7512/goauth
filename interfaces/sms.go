package interfaces

import (
	"context"

	"github.com/bete7512/goauth/models"
)

type SMSSenderInterface interface {
	SendVerificationSMS(ctx context.Context, user models.User, code string) error
	SendWelcomeSMS(ctx context.Context, user models.User) error
	SendTwoFactorSMS(ctx context.Context, user models.User, code string) error
}
