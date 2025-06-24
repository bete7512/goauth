package doc_api

// VerifyEmailPath returns the documentation for the verify email endpoint
func VerifyEmailPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Verify email address",
			"description": "Verifies a user's email address using a verification token",
			"tags":        []string{"Email Verification"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "query",
					"name":        "token",
					"description": "Email verification token",
					"required":    true,
					"type":        "string",
					"example":     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
				},
				{
					"in":          "query",
					"name":        "email",
					"description": "Email address for verification",
					"required":    true,
					"type":        "string",
					"example":     "user@example.com",
				},
				{
					"in":          "query",
					"name":        "recaptcha_token",
					"description": "Recaptcha token",
					"required":    false,
					"type":        "string",
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Email verified successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Email verified successfully",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid or expired token",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
			},
		},
		"post": map[string]interface{}{
			"summary":     "Verify email address",
			"description": "Verifies a user's email address using a verification token",
			"tags":        []string{"Email Verification"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Email address for verification",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/VerifyEmailRequest",
					},
				},
			},
		},
		"responses": map[string]interface{}{
			"200": map[string]interface{}{
				"description": "Email verified successfully",
			},
			"400": map[string]interface{}{
				"description": "Invalid or expired token",
				"schema": map[string]interface{}{
					"$ref": "#/definitions/Error",
				},
			},
		},
	}
}

// SendVerificationEmailPath returns the documentation for the resend verification email endpoint
func SendVerificationEmailPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Resend verification email",
			"description": "Resends a verification email to the user's email address",
			"tags":        []string{"Email Verification"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Email address for verification",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/ResendVerificationEmailRequest",
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Verification email sent successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Verification email sent",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid email address",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
				"404": map[string]interface{}{
					"description": "User not found",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
			},
		},
	}
}
