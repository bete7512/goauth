package doc_api

// SendPhoneVerificationPath returns the documentation for the send phone verification endpoint
func SendPhoneVerificationPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Send phone verification code",
			"description": "Sends a verification code to the user's phone number for verification",
			"tags":        []string{"Phone Verification"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Phone number for verification",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/SendPhoneVerificationRequest",
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Verification code sent successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "verification code sent successfully",
							},
							"status": map[string]interface{}{
								"type":    "string",
								"example": "sent",
							},
							"phone_number": map[string]interface{}{
								"type":    "string",
								"example": "+1***-***-1234",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid request or phone already verified",
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
