package oauth

// GitHubOAuthPath returns the documentation for the GitHub OAuth initiation endpoint
func GitHubOAuthPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Initiate GitHub OAuth",
			"description": "Redirects user to GitHub OAuth for authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"responses": map[string]interface{}{
				"302": map[string]interface{}{
					"description": "Redirect to GitHub OAuth",
				},
			},
		},
	}
}

// GitHubOAuthCallbackPath returns the documentation for the GitHub OAuth callback endpoint
func GitHubOAuthCallbackPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "GitHub OAuth callback",
			"description": "Handles the callback from GitHub OAuth authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "query",
					"name":        "code",
					"description": "Authorization code from GitHub",
					"required":    true,
					"type":        "string",
					"example":     "abc123def456...",
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
