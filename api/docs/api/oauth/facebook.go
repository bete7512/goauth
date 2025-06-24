package oauth

// FacebookOAuthPath returns the documentation for the Facebook OAuth initiation endpoint
func FacebookOAuthPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Initiate Facebook OAuth",
			"description": "Redirects user to Facebook OAuth for authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"responses": map[string]interface{}{
				"302": map[string]interface{}{
					"description": "Redirect to Facebook OAuth",
				},
			},
		},
	}
}

// FacebookOAuthCallbackPath returns the documentation for the Facebook OAuth callback endpoint
func FacebookOAuthCallbackPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Facebook OAuth callback",
			"description": "Handles the callback from Facebook OAuth authentication",
			"tags":        []string{"OAuth"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "query",
					"name":        "code",
					"description": "Authorization code from Facebook",
					"required":    true,
					"type":        "string",
					"example":     "AQDxXW...",
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
