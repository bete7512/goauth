package doc_api

// EnableTwoFactorPath returns the documentation for the enable two-factor authentication endpoint
func EnableTwoFactorPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Enable two-factor authentication",
			"description": "Enables two-factor authentication for the current user",
			"tags":        []string{"Two-Factor Authentication"},
			"produces":    []string{"application/json"},
			"security": []map[string]interface{}{
				{
					"BearerAuth": []string{},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Two-factor authentication enabled successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Two-factor authentication enabled",
							},
							"qr_code": map[string]interface{}{
								"type":    "string",
								"example": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
							},
							"secret": map[string]interface{}{
								"type":    "string",
								"example": "JBSWY3DPEHPK3PXP",
							},
						},
					},
				},
				"401": map[string]interface{}{
					"description": "Unauthorized",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
			},
		},
	}
}

// VerifyTwoFactorPath returns the documentation for the verify two-factor authentication endpoint
func VerifyTwoFactorPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Verify two-factor authentication",
			"description": "Verifies the two-factor authentication code",
			"tags":        []string{"Two-Factor Authentication"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"security": []map[string]interface{}{
				{
					"BearerAuth": []string{},
				},
			},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Two-factor authentication code",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/VerifyTwoFactorRequest",
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Two-factor authentication verified successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Two-factor authentication verified",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid code",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
				"401": map[string]interface{}{
					"description": "Unauthorized",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
			},
		},
	}
}

// DisableTwoFactorPath returns the documentation for the disable two-factor authentication endpoint
func DisableTwoFactorPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Disable two-factor authentication",
			"description": "Disables two-factor authentication for the current user",
			"tags":        []string{"Two-Factor Authentication"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"security": []map[string]interface{}{
				{
					"BearerAuth": []string{},
				},
			},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Two-factor authentication code for confirmation",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/DisableTwoFactorRequest",
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Two-factor authentication disabled successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Two-factor authentication disabled",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid code",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
				"401": map[string]interface{}{
					"description": "Unauthorized",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
			},
		},
	}
}
