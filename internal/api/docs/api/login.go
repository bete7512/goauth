package doc_api

// LoginPath returns the documentation for the login endpoint
func LoginPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "User login",
			"description": "Authenticates a user and returns access and refresh tokens",
			"tags":        []string{"Authentication"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "User login credentials",
					"required":    true,
					"schema": map[string]interface{}{
						"type":     "object",
						"required": []string{"email", "password"},
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
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Login successful",
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
							"user": map[string]interface{}{
								"$ref": "#/definitions/User",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid credentials",
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
