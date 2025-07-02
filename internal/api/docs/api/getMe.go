package doc_api

// GetMePath returns the documentation for the get me endpoint
func GetMePath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Get current user",
			"description": "Retrieves the current user's profile information",
			"tags":        []string{"User Management"},
			"produces":    []string{"application/json"},
			"security": []map[string]interface{}{
				{
					"BearerAuth": []string{},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "User profile retrieved successfully",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/User",
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
