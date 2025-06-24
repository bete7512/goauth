package doc_api

// ResetPasswordPath returns the documentation for the reset password endpoint

func ResetPasswordPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Reset password",
			"description": "Resets the user's password",
			"tags":        []string{"Authentication"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Password reset details",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/ResetPasswordRequest",
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Password Set Successfully",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid input",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type":    "string",
								"example": "Invalid Input",
							},
							"status": map[string]interface{}{
								"type":    "integer",
								"example": 400,
							},
							"message": map[string]interface{}{
								"type":    "string",
								"example": "The provided token or password have expired",
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
				"404": map[string]interface{}{
					"description": "User not found",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type":    "string",
								"example": "User not found",
							},
							"status": map[string]interface{}{
								"type":    "integer",
								"example": 404,
							},
							"message": map[string]interface{}{
								"type":    "string",
								"example": "User not found",
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
