package oauth

// AppleOAuthPath returns the documentation for the Apple OAuth initiation endpoint
func AppleOAuthPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Initiate Apple OAuth",
			"description": "Redirects user to Apple OAuth for authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"responses": map[string]interface{}{
				"302": map[string]interface{}{
					"description": "Redirect to Apple OAuth",
				},
			},
		},
	}
}

// AppleOAuthCallbackPath returns the documentation for the Apple OAuth callback endpoint
func AppleOAuthCallbackPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Apple OAuth callback",
			"description": "Handles the callback from Apple OAuth authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "query",
					"name":        "code",
					"description": "Authorization code from Apple",
					"required":    true,
					"type":        "string",
					"example":     "c1234567890...",
				},
				{
					"in":          "query",
					"name":        "state",
					"description": "State parameter for CSRF protection",
					"required":    false,
					"type":        "string",
					"example":     "random_state_string",
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "OAuth authentication successful",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "OAuth authentication successful",
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
					"description": "Invalid authorization code",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
				"401": map[string]interface{}{
					"description": "OAuth authentication failed",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
			},
		},
	}
}
