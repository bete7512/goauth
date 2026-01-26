// Package models is deprecated - use github.com/bete7512/goauth/pkg/models instead
// This file is kept for backward compatibility only
package models

import (
	"github.com/bete7512/goauth/pkg/models"
)

// Re-export types from pkg/models for backward compatibility
type (
	VerificationToken     = models.VerificationToken
	VerificationTokenType = models.VerificationTokenType
)

// Re-export constants
const (
	TokenTypeEmailVerification = models.TokenTypeEmailVerification
	TokenTypePhoneVerification = models.TokenTypePhoneVerification
	TokenTypePasswordReset     = models.TokenTypePasswordReset
	TokenTypeTwoFactorCode     = models.TokenTypeTwoFactorCode
)
