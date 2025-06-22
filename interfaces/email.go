package interfaces

import "github.com/bete7512/goauth/models"

type EmailSenderInterface interface {
	SendVerification(user models.User, redirectURL string) error
	SendWelcome(user models.User) error
	SendPasswordReset(user models.User, redirectURL string) error
	SendTwoFactorCode(user models.User, code string) error
	SendMagicLink(user models.User, redirectURL string) error
}
