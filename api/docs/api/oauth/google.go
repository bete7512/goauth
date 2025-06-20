package oauth

// GoogleOAuthPath returns the documentation for the Google OAuth initiation endpoint
func GoogleOAuthPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Initiate Google OAuth",
			"description": "Redirects user to Google OAuth for authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"responses": map[string]interface{}{
				"302": map[string]interface{}{
					"description": "Redirect to Google OAuth",
				},
			},
		},
	}
}

// GoogleOAuthCallbackPath returns the documentation for the Google OAuth callback endpoint
func GoogleOAuthCallbackPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Google OAuth callback",
			"description": "Handles the callback from Google OAuth authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "query",
					"name":        "code",
					"description": "Authorization code from Google",
					"required":    true,
					"type":        "string",
					"example":     "4/0AfJohXn...",
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
