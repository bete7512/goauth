package doc_api

// ForgotPasswordPath returns the documentation for the forgot password endpoint
func ForgotPasswordPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Forgot password",
			"description": "Sends a password reset email to the user",
			"tags":        []string{"Authentication"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "User email for password reset",
					"required":    true,
					"schema": map[string]interface{}{
						"type":     "object",
						"required": []string{"email"},
						"properties": map[string]interface{}{
							"email": map[string]interface{}{
								"type":    "string",
								"format":  "email",
								"example": "user@example.com",
							},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Password reset email sent successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Password reset email sent successfully",
							},
						},
					},
				},
				"401": map[string]interface{}{
					"description": "Unauthorized",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type":    "string",
								"example": "Unauthorized",
							},
							"status": map[string]interface{}{
								"type":    "integer",
								"example": 401,
							},
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Invalid or expired token",
							},
						},
					},
				},
				"500": map[string]interface{}{
					"description": "Internal server error",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type":    "string",
								"example": "Internal server error",
							},
							"status": map[string]interface{}{
								"type":    "integer",
								"example": 500,
							},
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Internal server error",
							},
						},
					},
				},
			},
		},
	}
}
