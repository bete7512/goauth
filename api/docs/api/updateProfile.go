package doc_api

// UpdateProfilePath returns the documentation for the update profile endpoint
func UpdateProfilePath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Update user profile",
			"description": "Updates the current user's profile information",
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
					"description": "Profile update details",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/UpdateProfileRequest",
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Profile updated successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Profile updated successfully",
							},
							"user": map[string]interface{}{
								"$ref": "#/definitions/User",
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
