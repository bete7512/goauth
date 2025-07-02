package doc_api

// RefreshTokenPath returns the documentation for the refresh token endpoint
func RefreshTokenPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Refresh access token",
			"description": "Uses the refresh token to get a new access token",
			"tags":        []string{"Authentication"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Refresh token details",
					"required":    true,
					"schema": map[string]interface{}{
						"type":     "object",
						"required": []string{"refreshToken"},
						"properties": map[string]interface{}{
							"refreshToken": map[string]interface{}{
								"type":    "string",
								"example": "your-refresh-token-here",
							},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Token refreshed successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"accessToken": map[string]interface{}{
								"type": "string",
							},
							"refreshToken": map[string]interface{}{
								"type": "string",
							},
							"expiresIn": map[string]interface{}{
								"type":    "integer",
								"example": 3600,
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
