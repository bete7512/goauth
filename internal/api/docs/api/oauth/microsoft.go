package oauth

// MicrosoftOAuthPath returns the documentation for the Microsoft OAuth initiation endpoint
func MicrosoftOAuthPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Initiate Microsoft OAuth",
			"description": "Redirects user to Microsoft OAuth for authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"responses": map[string]interface{}{
				"302": map[string]interface{}{
					"description": "Redirect to Microsoft OAuth",
				},
			},
		},
	}
}

// MicrosoftOAuthCallbackPath returns the documentation for the Microsoft OAuth callback endpoint
func MicrosoftOAuthCallbackPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Microsoft OAuth callback",
			"description": "Handles the callback from Microsoft OAuth authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "query",
					"name":        "code",
					"description": "Authorization code from Microsoft",
					"required":    true,
					"type":        "string",
					"example":     "M.R3_BAY.c0...",
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
