package dto

import (
	"fmt"
	"regexp"
	"time"

	"github.com/bete7512/goauth/pkg/models"
)

// ── Request DTOs ────────────────────────────────────────────────────────────

// SendInvitationRequest represents a request to send a standalone invitation.
type SendInvitationRequest struct {
	Email    string `json:"email"`
	Purpose  string `json:"purpose,omitempty"`
	Metadata string `json:"metadata,omitempty"`
}

func (r *SendInvitationRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	if !isValidEmail(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// AcceptInvitationRequest represents invitation acceptance.
// Name and Password are required only when the invited user doesn't have an account yet.
type AcceptInvitationRequest struct {
	Token    string `json:"token"`
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

func (r *AcceptInvitationRequest) Validate() error {
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	return nil
}

// AcceptResultDTO is the response after accepting an invitation.
type AcceptResultDTO struct {
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token"`
	User         *AcceptUserDTO `json:"user"`
	IsNewUser    bool           `json:"is_new_user"`
}

// AcceptUserDTO is a minimal user representation in accept responses.
type AcceptUserDTO struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name,omitempty"`
	EmailVerified bool   `json:"email_verified"`
}

// DeclineInvitationRequest represents invitation decline.
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

// InvitationDTO represents invitation data in responses.
type InvitationDTO struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	Purpose    string     `json:"purpose"`
	InviterID  string     `json:"inviter_id"`
	Status     string     `json:"status"`
	Metadata   string     `json:"metadata,omitempty"`
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
		Email:      inv.Email,
		Purpose:    inv.Purpose,
		InviterID:  inv.InviterID,
		Status:     inv.Status,
		Metadata:   inv.Metadata,
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

// ── Validation helpers ──────────────────────────────────────────────────────

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func isValidEmail(email string) bool {
	return len(email) <= 254 && emailRegex.MatchString(email)
}
