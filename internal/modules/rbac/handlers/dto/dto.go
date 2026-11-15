// Package dto holds the request and response bodies of the rbac endpoints.
package dto

import (
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/pkg/models"
)

// RoleDTO is a role as the API returns it.
type RoleDTO struct {
	Key         string     `json:"key"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Grants      []string   `json:"grants"`
	Scope       string     `json:"scope"`
	OrgID       string     `json:"org_id,omitempty"`
	System      bool       `json:"system"`
	Implied     bool       `json:"implied"`
	CreatedBy   string     `json:"created_by,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// CreateRoleRequest is the body of the create-role endpoints.
type CreateRoleRequest struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Grants      []string `json:"grants"`
}

// Validate checks the fields that must be present. The service validates
// their content.
func (r *CreateRoleRequest) Validate() error {
	if r.Key == "" {
		return errors.New("key is required")
	}
	if r.Name == "" {
		return errors.New("name is required")
	}
	return nil
}

// UpdateRoleRequest is the body of the update-role endpoints. Fields left
// out are not changed.
type UpdateRoleRequest struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	Grants      *[]string `json:"grants,omitempty"`
}

// Validate requires at least one field.
func (r *UpdateRoleRequest) Validate() error {
	if r.Name == nil && r.Description == nil && r.Grants == nil {
		return errors.New("at least one of name, description or grants is required")
	}
	return nil
}

// SetRolesRequest is the body of the set-roles endpoints: the complete list
// of roles the user should be assigned in the scope.
type SetRolesRequest struct {
	Roles *[]string `json:"roles"`
}

// Validate requires the list, which may be empty to remove every role.
func (r *SetRolesRequest) Validate() error {
	if r.Roles == nil {
		return errors.New("roles is required; send an empty list to remove every role")
	}
	return nil
}

// HeldRoleDTO is one role a user holds.
type HeldRoleDTO struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Scope   string `json:"scope"`
	System  bool   `json:"system"`
	Implied bool   `json:"implied"`
}

// UserRolesDTO is what a user holds in a scope. Permissions are grant
// patterns such as "invoice:*"; a client matches them the way the server does.
type UserRolesDTO struct {
	UserID      string        `json:"user_id"`
	Scope       string        `json:"scope"`
	OrgID       string        `json:"org_id,omitempty"`
	Roles       []HeldRoleDTO `json:"roles"`
	Permissions []string      `json:"permissions"`
}

// AssignmentDTO is one role assignment.
type AssignmentDTO struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	Scope     string    `json:"scope"`
	OrgID     string    `json:"org_id,omitempty"`
	GrantedBy string    `json:"granted_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// PermissionDTO is one entry of the permission catalog.
type PermissionDTO struct {
	Permission  string `json:"permission"`
	Description string `json:"description,omitempty"`
}

// RoleToDTO converts a role view.
func RoleToDTO(role *services.RoleView) *RoleDTO {
	grants := role.Grants
	if grants == nil {
		grants = []string{}
	}
	return &RoleDTO{
		Key:         role.Key,
		Name:        role.Name,
		Description: role.Description,
		Grants:      grants,
		Scope:       string(role.Scope),
		OrgID:       role.OrgID,
		System:      role.System,
		Implied:     role.Implied,
		CreatedBy:   role.CreatedBy,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	}
}

// RolesToDTO converts a list of role views.
func RolesToDTO(roles []*services.RoleView) []*RoleDTO {
	out := make([]*RoleDTO, 0, len(roles))
	for _, role := range roles {
		out = append(out, RoleToDTO(role))
	}
	return out
}

// UserRolesToDTO converts what a user holds.
func UserRolesToDTO(roles *services.UserRoles) *UserRolesDTO {
	held := make([]HeldRoleDTO, 0, len(roles.Roles))
	for _, role := range roles.Roles {
		held = append(held, HeldRoleDTO{Key: role.Key, Name: role.Name, Scope: string(role.Scope), System: role.System, Implied: role.Implied})
	}
	permissions := roles.Grants
	if permissions == nil {
		permissions = []string{}
	}
	return &UserRolesDTO{
		UserID:      roles.UserID,
		Scope:       string(roles.Scope.Type),
		OrgID:       roles.Scope.OrgID(),
		Roles:       held,
		Permissions: permissions,
	}
}

// AssignmentsToDTO converts a list of assignments.
func AssignmentsToDTO(assignments []*models.RoleAssignment) []*AssignmentDTO {
	out := make([]*AssignmentDTO, 0, len(assignments))
	for _, assignment := range assignments {
		item := &AssignmentDTO{
			UserID:    assignment.UserID,
			Role:      assignment.RoleKey,
			Scope:     assignment.ScopeType,
			GrantedBy: assignment.GrantedBy,
			CreatedAt: assignment.CreatedAt,
		}
		if assignment.ScopeType == models.RoleScopeOrg {
			item.OrgID = assignment.ScopeID
		}
		out = append(out, item)
	}
	return out
}
