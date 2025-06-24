package doc_api

// DeactivateUserPath returns the documentation for the deactivate user endpoint
func DeactivateUserPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Deactivate user account",
			"description": "Deactivates the current user's account",
			"tags":        []string{"User Management"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"security": []map[string]interface{}{
				{
					"BearerAuth": []string{},
				},
			},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Deactivation confirmation",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/DeactivateUserRequest",
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "User account deactivated successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Account deactivated successfully",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid input",
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
