package doc_api


// RegisterPath returns the documentation for the register endpoint
func RegisterPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Register a new user",
			"description": "Creates a new user account",
			"tags":        []string{"Authentication"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "User registration details",
					"required":    true,
					"schema": map[string]interface{}{
						"$ref": "#/definitions/RegisterRequest",
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "User successfully registered",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "User registered successfully",
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
				"409": map[string]interface{}{
					"description": "User already exists",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
			},
		},
	}
}