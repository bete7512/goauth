package definitions

// UserDefinition returns the User schema definition
func UserDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"id": map[string]interface{}{
				"type":    "string",
				"format":  "uuid",
				"example": "123e4567-e89b-12d3-a456-426614174000",
			},
			"email": map[string]interface{}{
				"type":    "string",
				"format":  "email",
				"example": "user@example.com",
			},
			"first_name": map[string]interface{}{
				"type":    "string",
				"example": "John",
			},
			"last_name": map[string]interface{}{
				"type":    "string",
				"example": "Doe",
			},
			"email_verified": map[string]interface{}{
				"type":    "boolean",
				"example": true,
			},
			"two_factor_enabled": map[string]interface{}{
				"type":    "boolean",
				"example": false,
			},
			"created_at": map[string]interface{}{
				"type":   "string",
				"format": "date-time",
			},
			"updated_at": map[string]interface{}{
				"type":   "string",
				"format": "date-time",
			},
		},
	}
}
