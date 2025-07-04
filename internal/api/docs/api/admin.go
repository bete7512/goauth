package doc_api

// AdminPaths returns the documentation for all admin endpoints
func AdminPaths() map[string]interface{} {
	return map[string]interface{}{
		"/admin/users":               AdminUsersPath(),
		"/admin/users/{id}":          AdminUserByIDPath(),
		"/admin/users/{id}/activate": AdminUserActivatePath(),
		"/admin/users/bulk":          AdminUsersBulkPath(),
		"/admin/audit-logs":          AdminAuditLogsPath(),
		"/admin/users/export":        AdminUsersExportPath(),
	}
}

// GET /admin/users
func AdminUsersPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "List users",
			"description": "Admin endpoint to list all users",
			"tags":        []string{"Admin"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
				{"in": "query", "name": "page", "type": "integer", "required": false, "description": "Page number"},
				{"in": "query", "name": "limit", "type": "integer", "required": false, "description": "Items per page"},
				{"in": "query", "name": "sort_by", "type": "string", "required": false, "description": "Sort by field"},
				{"in": "query", "name": "sort_dir", "type": "string", "required": false, "description": "Sort direction (asc/desc)"},
				{"in": "query", "name": "search", "type": "string", "required": false, "description": "Search query"},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "List of users", "schema": map[string]interface{}{"type": "object"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
		"post": map[string]interface{}{
			"summary":     "Bulk user actions",
			"description": "Admin endpoint to perform bulk actions on users",
			"tags":        []string{"Admin"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
				{"in": "body", "name": "body", "required": true, "schema": map[string]interface{}{"type": "object"}},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "Bulk action result", "schema": map[string]interface{}{"type": "object"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
	}
}

// GET, PUT, PATCH, DELETE /admin/users/{id}
func AdminUserByIDPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Get user by ID",
			"description": "Admin endpoint to get a user by ID",
			"tags":        []string{"Admin"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
				{"in": "path", "name": "id", "type": "string", "required": true, "description": "User ID"},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "User details", "schema": map[string]interface{}{"type": "object"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"404": map[string]interface{}{"description": "Not found", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
		"put": map[string]interface{}{
			"summary":     "Update user by ID",
			"description": "Admin endpoint to update a user by ID",
			"tags":        []string{"Admin"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
				{"in": "path", "name": "id", "type": "string", "required": true, "description": "User ID"},
				{"in": "body", "name": "body", "required": true, "schema": map[string]interface{}{"type": "object"}},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "User updated", "schema": map[string]interface{}{"type": "object"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"404": map[string]interface{}{"description": "Not found", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
		"patch": map[string]interface{}{
			"summary":     "Patch user by ID",
			"description": "Admin endpoint to patch a user by ID",
			"tags":        []string{"Admin"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
				{"in": "path", "name": "id", "type": "string", "required": true, "description": "User ID"},
				{"in": "body", "name": "body", "required": true, "schema": map[string]interface{}{"type": "object"}},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "User patched", "schema": map[string]interface{}{"type": "object"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"404": map[string]interface{}{"description": "Not found", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
		"delete": map[string]interface{}{
			"summary":     "Delete user by ID",
			"description": "Admin endpoint to delete a user by ID",
			"tags":        []string{"Admin"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
				{"in": "path", "name": "id", "type": "string", "required": true, "description": "User ID"},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "User deleted", "schema": map[string]interface{}{"type": "object"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"404": map[string]interface{}{"description": "Not found", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
	}
}

// POST /admin/users/{id}/activate
func AdminUserActivatePath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Activate user by ID",
			"description": "Admin endpoint to activate a user by ID",
			"tags":        []string{"Admin"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
				{"in": "path", "name": "id", "type": "string", "required": true, "description": "User ID"},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "User activated", "schema": map[string]interface{}{"type": "object"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"404": map[string]interface{}{"description": "Not found", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
	}
}

// POST /admin/users/bulk
func AdminUsersBulkPath() map[string]interface{} {
	return map[string]interface{}{
		"post": map[string]interface{}{
			"summary":     "Bulk user actions",
			"description": "Admin endpoint to perform bulk actions on users",
			"tags":        []string{"Admin"},
			"consumes":    []string{"application/json"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
				{"in": "body", "name": "body", "required": true, "schema": map[string]interface{}{"type": "object"}},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "Bulk action result", "schema": map[string]interface{}{"type": "object"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
	}
}

// GET /admin/audit-logs
func AdminAuditLogsPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Get audit logs",
			"description": "Admin endpoint to get audit logs",
			"tags":        []string{"Admin"},
			"produces":    []string{"application/json"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "Audit logs", "schema": map[string]interface{}{"type": "object"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
	}
}

// GET /admin/users/export
func AdminUsersExportPath() map[string]interface{} {
	return map[string]interface{}{
		"get": map[string]interface{}{
			"summary":     "Export users",
			"description": "Admin endpoint to export users as CSV or JSON",
			"tags":        []string{"Admin"},
			"produces":    []string{"application/json", "text/csv"},
			"parameters": []map[string]interface{}{
				{"in": "header", "name": "Authorization", "type": "string", "required": true, "description": "Bearer token"},
			},
			"responses": map[string]interface{}{
				"200": map[string]interface{}{"description": "Exported users", "schema": map[string]interface{}{"type": "file"}},
				"401": map[string]interface{}{"description": "Unauthorized", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
				"403": map[string]interface{}{"description": "Forbidden", "schema": map[string]interface{}{"$ref": "#/definitions/Error"}},
			},
		},
	}
}
