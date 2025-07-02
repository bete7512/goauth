package doc_api

// LogoutPath returns the documentation for the logout endpoint
func LogoutPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "User logout",
			"description": "Logs out the user and invalidates the refresh token",
			"tags":        []string{"Authentication"},
			"produces":    []string{"application/json"},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Logout successful",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "User logged out successfully",
							},
						},
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
