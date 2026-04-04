package dto

import (
	"fmt"
	"regexp"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// ── Request DTOs ────────────────────────────────────────────────────────────

// CreateOrgRequest represents organization creation request
type CreateOrgRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug,omitempty"`
}

func (r *CreateOrgRequest) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.Slug != "" && !isValidSlug(r.Slug) {
		return fmt.Errorf("slug must be lowercase alphanumeric with hyphens, 2-64 characters")
	}
	return nil
}

// UpdateOrgRequest represents organization update request
type UpdateOrgRequest struct {
	Name     *string `json:"name,omitempty"`
	LogoURL  *string `json:"logo_url,omitempty"`
	Metadata *string `json:"metadata,omitempty"`
}

func (r *UpdateOrgRequest) Validate() error {
	if r.Name == nil && r.LogoURL == nil && r.Metadata == nil {
		return fmt.Errorf("at least one field must be provided for update")
	}
	if r.Name != nil && *r.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if r.LogoURL != nil && *r.LogoURL != "" && !isValidURL(*r.LogoURL) {
		return fmt.Errorf("invalid logo URL format")
	}
	return nil
}

// InviteRequest represents organization invitation request
type InviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
}

func (r *InviteRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	if !isValidEmail(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	if r.Role != "" && !types.IsValidOrgRole(r.Role) {
		return fmt.Errorf("invalid role: must be owner, admin, or member")
	}
	return nil
}

// UpdateMemberRoleRequest represents member role update request
type UpdateMemberRoleRequest struct {
	Role string `json:"role"`
}

func (r *UpdateMemberRoleRequest) Validate() error {
	if r.Role == "" {
		return fmt.Errorf("role is required")
	}
	if !types.IsValidOrgRole(r.Role) {
		return fmt.Errorf("invalid role: must be owner, admin, or member")
	}
	return nil
}

// SwitchOrgRequest represents organization switch request
type SwitchOrgRequest struct {
	OrgID string `json:"org_id"`
}

func (r *SwitchOrgRequest) Validate() error {
	if r.OrgID == "" {
		return fmt.Errorf("org_id is required")
	}
	return nil
}

// AcceptInvitationRequest represents invitation acceptance request
type AcceptInvitationRequest struct {
	Token string `json:"token"`
}

func (r *AcceptInvitationRequest) Validate() error {
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	return nil
}

// DeclineInvitationRequest represents invitation decline request
type DeclineInvitationRequest struct {
	Token string `json:"token"`
}

func (r *DeclineInvitationRequest) Validate() error {
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	return nil
}

// ── Response DTOs ───────────────────────────────────────────────────────────

// OrgDTO represents organization data in responses
type OrgDTO struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	OwnerID   string     `json:"owner_id"`
	LogoURL   string     `json:"logo_url,omitempty"`
	Metadata  string     `json:"metadata,omitempty"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func OrgToDTO(org *models.Organization) *OrgDTO {
	if org == nil {
		return nil
	}
	return &OrgDTO{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		OwnerID:   org.OwnerID,
		LogoURL:   org.LogoURL,
		Metadata:  org.Metadata,
		Active:    org.Active,
		CreatedAt: org.CreatedAt,
		UpdatedAt: org.UpdatedAt,
	}
}

func OrgsToDTO(orgs []*models.Organization) []*OrgDTO {
	dtos := make([]*OrgDTO, len(orgs))
	for i, org := range orgs {
		dtos[i] = OrgToDTO(org)
	}
	return dtos
}

// MemberDTO represents organization member data in responses
type MemberDTO struct {
	ID       string    `json:"id"`
	OrgID    string    `json:"org_id"`
	UserID   string    `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
	User     *UserDTO  `json:"user,omitempty"`
}

// UserDTO represents minimal user data embedded in member responses
type UserDTO struct {
	ID            string    `json:"id"`
	Name          string    `json:"name,omitempty"`
	FirstName     string    `json:"first_name,omitempty"`
	LastName      string    `json:"last_name,omitempty"`
	Email         string    `json:"email"`
	Username      string    `json:"username,omitempty"`
	Avatar        string    `json:"avatar,omitempty"`
	Active        bool      `json:"active"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

func UserToDTO(user *models.User) *UserDTO {
	if user == nil {
		return nil
	}
	return &UserDTO{
		ID:            user.ID,
		Name:          user.Name,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Email:         user.Email,
		Username:      user.Username,
		Avatar:        user.Avatar,
		Active:        user.Active,
		EmailVerified: user.EmailVerified,
		CreatedAt:     user.CreatedAt,
	}
}

// MemberWithUser is the service-level type that pairs a member with its user
type MemberWithUser struct {
	models.OrganizationMember
	User *models.User `json:"user,omitempty"`
}

func MemberToDTO(m *MemberWithUser) *MemberDTO {
	if m == nil {
		return nil
	}
	dto := &MemberDTO{
		ID:       m.ID,
		OrgID:    m.OrgID,
		UserID:   m.UserID,
		Role:     m.Role,
		JoinedAt: m.JoinedAt,
	}
	if m.User != nil {
		dto.User = UserToDTO(m.User)
	}
	return dto
}

func MembersToDTO(members []*MemberWithUser) []*MemberDTO {
	dtos := make([]*MemberDTO, len(members))
	for i, m := range members {
		dtos[i] = MemberToDTO(m)
	}
	return dtos
}

// InvitationDTO represents invitation data in responses
type InvitationDTO struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	InviterID  string     `json:"inviter_id"`
	Status     string     `json:"status"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
}

func InvitationToDTO(inv *models.Invitation) *InvitationDTO {
	if inv == nil {
		return nil
	}
	return &InvitationDTO{
		ID:         inv.ID,
		OrgID:      inv.OrgID,
		Email:      inv.Email,
		Role:       inv.Role,
		InviterID:  inv.InviterID,
		Status:     inv.Status,
		ExpiresAt:  inv.ExpiresAt,
		CreatedAt:  inv.CreatedAt,
		AcceptedAt: inv.AcceptedAt,
	}
}

func InvitationsToDTO(invs []*models.Invitation) []*InvitationDTO {
	dtos := make([]*InvitationDTO, len(invs))
	for i, inv := range invs {
		dtos[i] = InvitationToDTO(inv)
	}
	return dtos
}

// SwitchOrgResponse represents the response for switching organizations
type SwitchOrgResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// MemberCreatedDTO represents a newly created member in responses (from accept invitation)
type MemberCreatedDTO struct {
	ID       string    `json:"id"`
	OrgID    string    `json:"org_id"`
	UserID   string    `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

func MemberCreatedToDTO(m *models.OrganizationMember) *MemberCreatedDTO {
	if m == nil {
		return nil
	}
	return &MemberCreatedDTO{
		ID:       m.ID,
		OrgID:    m.OrgID,
		UserID:   m.UserID,
		Role:     m.Role,
		JoinedAt: m.JoinedAt,
	}
}

// ── Validation helpers ──────────────────────────────────────────────────────

var (
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	slugRegex  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)
	urlRegex   = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
)

func isValidEmail(email string) bool {
	return len(email) <= 254 && emailRegex.MatchString(email)
}

func isValidSlug(slug string) bool {
	return slugRegex.MatchString(slug)
}

func isValidURL(url string) bool {
	return urlRegex.MatchString(url)
}
