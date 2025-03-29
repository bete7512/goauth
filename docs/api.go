package docs

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
						"type":     "object",
						"required": []string{"email", "password"},
						"properties": map[string]interface{}{
							"email": map[string]interface{}{
								"type":    "string",
								"format":  "email",
								"example": "user@example.com",
							},
							"password": map[string]interface{}{
								"type":    "string",
								"format":  "password",
								"example": "Password123!",
							},
							"firstName": map[string]interface{}{
								"type":    "string",
								"example": "John",
							},
							"lastName": map[string]interface{}{
								"type":    "string",
								"example": "Doe",
							},
						},
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

// LoginPath returns the documentation for the login endpoint
func LoginPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "User login",
			"description": "Authenticates a user and returns access and refresh tokens",
			"tags":        []string{"Authentication"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "User login credentials",
					"required":    true,
					"schema": map[string]interface{}{
						"type":     "object",
						"required": []string{"email", "password"},
						"properties": map[string]interface{}{
							"email": map[string]interface{}{
								"type":    "string",
								"format":  "email",
								"example": "user@example.com",
							},
							"password": map[string]interface{}{
								"type":    "string",
								"format":  "password",
								"example": "Password123!",
							},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Login successful",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"accessToken": map[string]interface{}{
								"type": "string",
							},
							"refreshToken": map[string]interface{}{
								"type": "string",
							},
							"expiresIn": map[string]interface{}{
								"type":    "integer",
								"example": 3600,
							},
							"user": map[string]interface{}{
								"$ref": "#/definitions/User",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid credentials",
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

// RefreshTokenPath returns the documentation for the refresh token endpoint
func RefreshTokenPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Refresh access token",
			"description": "Uses the refresh token to get a new access token",
			"tags":        []string{"Authentication"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Refresh token details",
					"required":    true,
					"schema": map[string]interface{}{
						"type":     "object",
						"required": []string{"refreshToken"},
						"properties": map[string]interface{}{
							"refreshToken": map[string]interface{}{
								"type":    "string",
								"example": "your-refresh-token-here",
							},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Token refreshed successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"accessToken": map[string]interface{}{
								"type": "string",
							},
							"refreshToken": map[string]interface{}{
								"type": "string",
							},
							"expiresIn": map[string]interface{}{
								"type":    "integer",
								"example": 3600,
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid credentials",
					"schema":      "$ref: #/definitions/Error",
				},
				"statusCode":  401,
				"description": "Unauthorized",
				"schema":      "$ref: #/definitions/Error",
			},
		},
	}
}

// ForgotPasswordPath returns the documentation for the forgot password endpoint
func ForgotPasswordPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Forgot password",
			"description": "Sends a password reset email to the user",
			"tags":        []string{"Authentication"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "User email for password reset",
					"required":    true,
					"schema": map[string]interface{}{
						"type":     "object",
						"required": []string{"email"},
						"properties": map[string]interface{}{
							"email": map[string]interface{}{
								"type":    "string",
								"format":  "email",
								"example": "user@example.com",
							},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Password reset email sent successfully",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Password reset email sent successfully",
							},
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid credentials",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
				"statusCode":  401,
				"description": "Unauthorized",
				"schema": map[string]interface{}{
					"$ref": "#/definitions/Error",
				},
			},
		},
	}
}

// ResetPasswordPath returns the documentation for the reset password endpoint

func ResetPasswordPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Reset password",
			"description": "Resets the user's password",
			"tags":        []string{"Authentication"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{
					"in":          "body",
					"name":        "body",
					"description": "Password reset details",
					"required":    true,
					"schema": map[string]interface{}{
						"type":     "object",
						"required": []string{"password", "token"},
						"properties": map[string]interface{}{
							"password": map[string]interface{}{
								"type":    "string",
								"example": "new-password-here",	
							},
							"token": map[string]interface{}{
								"type":    "string",
								"example": "your-reset-token-here",
							},
						},
					},
				},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Password reset successful",
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"message": map[string]interface{}{
								"type":    "string",
								"example": "Password reset successful",
							},	
						},
					},
				},
				"400": map[string]interface{}{
					"description": "Invalid credentials",
					"schema": map[string]interface{}{
						"$ref": "#/definitions/Error",
					},
				},
				"statusCode":  401,
				"description": "Unauthorized",
				"schema": map[string]interface{}{
					"$ref": "#/definitions/Error",
				},
			},
		},
	}
}