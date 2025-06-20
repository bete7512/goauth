package definitions

func UserResponseDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"id": map[string]interface{}{
				"type":    "string",
				"format":  "uuid",
				"example": "123e4567-e89b-12d3-a456-426614174000",
			},
			"first_name": map[string]interface{}{
				"type":    "string",
				"example": "John",
			},
			"last_name": map[string]interface{}{
				"type":    "string",
				"example": "Doe",
			},
			"email": map[string]interface{}{
				"type":    "string",
				"format":  "email",
				"example": "user@example.com",
			},
			"created_at": map[string]interface{}{
				"type":   "string",
				"format": "date-time",
			},
		},
	}
}
