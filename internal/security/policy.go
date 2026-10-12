package security

import (
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// CheckEligibility is shared by credential issuance and request validation.
func CheckEligibility(user *models.User, cfg *config.CoreConfig) *types.GoAuthError {
	if user == nil || !user.Active {
		return types.NewUnauthorizedError()
	}
	if cfg != nil {
		if cfg.RequireEmailVerification && !user.EmailVerified {
			return types.NewGoAuthError(types.ErrUnauthorized, "email verification required", 403)
		}
		if cfg.RequirePhoneVerification && !user.PhoneNumberVerified {
			return types.NewGoAuthError(types.ErrUnauthorized, "phone verification required", 403)
		}
	}
	return nil
}
