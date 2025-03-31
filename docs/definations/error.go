package definitions

// ErrorDefinition returns the Error schema definition
func ErrorDefinition() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"error": map[string]interface{}{
				"type":    "string",
				"example": "Invalid credentials",
			},
			"status": map[string]interface{}{
				"type":    "integer",
				"example": 400,
			},
			"message": map[string]interface{}{
				"type":    "string",
				"example": "The provided email or password is incorrect",
			},
		},
	}
}
