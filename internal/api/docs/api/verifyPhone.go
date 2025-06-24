package doc_api

// VerifyPhonePath returns the documentation for the verify phone endpoint
func VerifyPhonePath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Verify phone number (GET)",
			"description": "Verifies a user's phone number using a verification code via GET request",
			"tags":        []string{"Phone Verification"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "query",
					"name":        "code",
					"description": "Phone verification code",
					"required":    true,
					"type":        "string",
					"example":     "123456",
				},
				{
					"in":          "query",
					"name":        "phone_number",
					"description": "Phone number to verify",
					"required":    true,
					"type":        "string",
					"example":     "+1234567890",
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Phone verified successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Phone verified successfully",
							},
							"status": map[string]interface{}{
								"type":    "string",
								"example": "verified",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid or expired verification code",
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
				"500": map[string]interface{}{
					"description": "Internal server error",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
			},
		},
		"post": map[string]interface{}{
			"summary":     "Verify phone number (POST)",
			"description": "Verifies a user's phone number using a verification code via POST request",
			"tags":        []string{"Phone Verification"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Phone verification details",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/VerifyPhoneRequest",
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Phone verified successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Phone verified successfully",
							},
							"status": map[string]interface{}{
								"type":    "string",
								"example": "verified",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid or expired verification code",
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
				"500": map[string]interface{}{
					"description": "Internal server error",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
			},
		},
	}
}
