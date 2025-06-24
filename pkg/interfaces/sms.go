package interfaces

import (
	"context"

	"github.com/bete7512/goauth/pkg/types"
)

type SMSSenderInterface interface {
	SendVerificationSMS(ctx context.Context, user types.User, code string) error
	SendWelcomeSMS(ctx context.Context, user types.User) error
	SendTwoFactorSMS(ctx context.Context, user types.User, code string) error
}
