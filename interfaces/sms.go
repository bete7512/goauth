package interfaces

import "github.com/bete7512/goauth/models"

type SMSSenderInterface interface {
	SendVerificationCode(user models.User, code string) error
	SendWelcome(user models.User) error
	SendTwoFactorCode(user models.User, code string) error
}