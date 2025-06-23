package definitions

func RegisterRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"first_name": map[string]interface{}{
				"type":    "string",
				"example": "John",
			},
			"last_name": map[string]interface{}{
				"type":    "string",
				"example": "Doe",
			},
			"email": map[string]interface{}{
				"type":    "string",
				"format":  "email",
				"example": "user@example.com",
			},
			"phone_number": map[string]interface{}{
				"type":    "string",
				"example": "+1234567890",
			},
			"password": map[string]interface{}{
				"type":    "string",
				"format":  "password",
				"example": "Password123!",
			},
			"recaptcha_token": map[string]interface{}{
				"type":     "string",
				"example":  "03AFcWeA...",
				"required": false,
			},
		},
	}
}

func LoginRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"email": map[string]interface{}{
				"type":    "string",
				"format":  "email",
				"example": "user@example.com",
			},
			"password": map[string]interface{}{
				"type":    "string",
				"format":  "password",
				"example": "Password123!",
			},
			"two_factor_code": map[string]interface{}{
				"type":    "string",
				"example": "123456",
			},
		},
	}
}

func RefreshTokenRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"refresh_token": map[string]interface{}{
				"type":    "string",
				"example": "your-refresh-token-here",
			},
		},
	}
}

func ForgotPasswordRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"email": map[string]interface{}{
				"type":    "string",
				"format":  "email",
				"example": "user@example.com",
			},
		},
	}
}
func ResetPasswordRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"token": map[string]interface{}{
				"type":    "string",
				"example": "your-reset-token-here",
			},
			"new_password": map[string]interface{}{
				"type":    "string",
				"example": "new-password-here",
			},
		},
	}
}

func UpdateProfileRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"first_name": map[string]interface{}{
				"type":    "string",
				"example": "John",
			},
			"last_name": map[string]interface{}{
				"type":    "string",
				"example": "Doe",
			},
			"phone_number": map[string]interface{}{
				"type":    "string",
				"example": "+1234567890",
			},
			"address": map[string]interface{}{
				"type":    "string",
				"example": "123 Main St.",
			},
			"profile_image_url": map[string]interface{}{
				"type":    "string",
				"example": "https://example.com/profile.jpg",
			},
		},
	}
}

func ChangePasswordRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"current_password": map[string]interface{}{
				"type":    "string",
				"example": "current-password-here",
			},
			"new_password": map[string]interface{}{
				"type":    "string",
				"example": "new-password-here",
			},
		},
	}
}
func DeactivateUserRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"password": map[string]interface{}{
				"type":    "string",
				"example": "current-password-here",
			},
		},
	}
}

func VerifyTwoFactorRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"code": map[string]interface{}{
				"type":    "string",
				"example": "123456",
			},
		},
	}
}

func DisableTwoFactorRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"password": map[string]interface{}{
				"type":    "string",
				"example": "current-password-here",
			},
		},
	}
}

func VerifyEmailRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"token": map[string]interface{}{
				"type":    "string",
				"example": "your-reset-token-here",
			},
			"email": map[string]interface{}{
				"type":    "string",
				"example": "user@example.com",
			},
			"recaptcha_token": map[string]interface{}{
				"type":     "string",
				"example":  "03AFcWeA...",
				"required": false,
			},
		},
	}
}

func ResendVerificationEmailRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"email": map[string]interface{}{
				"type":    "string",
				"example": "user@example.com",
			},
			"recaptcha_token": map[string]interface{}{
				"type":     "string",
				"example":  "03AFcWeA...",
				"required": false,
			},
		},
	}
}

func SendPhoneVerificationRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"phone_number": map[string]interface{}{
				"type":    "string",
				"example": "+1234567890",
			},
			"recaptcha_token": map[string]interface{}{
				"type":    "string",
				"example": "03AFcWeA...",
			},
		},
		"required": []string{"phone_number"},
	}
}

func VerifyPhoneRequestDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"code": map[string]interface{}{
				"type":    "string",
				"example": "123456",
			},
			"phone_number": map[string]interface{}{
				"type":    "string",
				"example": "+1234567890",
			},
			"recaptcha_token": map[string]interface{}{
				"type":    "string",
				"example": "03AFcWeA...",
			},
		},
		"required": []string{"code", "phone_number"},
	}
}
