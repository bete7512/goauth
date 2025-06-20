package doc_api

// MagicLinkPath returns the documentation for the magic link authentication endpoint
func MagicLinkPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Send magic link",
			"description": "Sends a magic link to the user's email address for passwordless authentication",
			"tags":        []string{"Authentication"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Email address for magic link",
					"required":    true,
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"email": map[string]interface{}{
								"type":    "string",
								"example": "user@example.com",
							},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Magic link sent successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Magic link sent to your email",
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

// MagicLinkCallbackPath returns the documentation for the magic link callback endpoint
func MagicLinkCallbackPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Verify magic link",
			"description": "Verifies a magic link token and authenticates the user",
			"tags":        []string{"Authentication"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "query",
					"name":        "token",
					"description": "Magic link token",
					"required":    true,
					"type":        "string",
					"example":     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Authentication successful",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Authentication successful",
							},
							"access_token": map[string]interface{}{
								"type":    "string",
								"example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
							},
							"refresh_token": map[string]interface{}{
								"type":    "string",
								"example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
							},
							"user": map[string]interface{}{
								"$ref": "#/definitions/User",
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
	}
}
