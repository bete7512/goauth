package dto

import (
	"errors"
	"regexp"
	"strings"
)

// Standard pagination request
type PaginationRequest struct {
	Page  int    `json:"page" form:"page" validate:"min=1" example:"1"`
	Limit int    `json:"limit" form:"limit" validate:"min=1,max=100" example:"10"`
	Sort  string `json:"sort" form:"sort" validate:"oneof=created_at updated_at email first_name last_name" example:"created_at"`
	Order string `json:"order" form:"order" validate:"oneof=asc desc" example:"desc"`
}

func (p *PaginationRequest) Validate() error {
	if p.Page < 1 {
		p.Page = 1
	}
	if p.Limit < 1 || p.Limit > 100 {
		p.Limit = 10
	}
	if p.Sort == "" {
		p.Sort = "created_at"
	}
	if p.Order == "" || (p.Order != "asc" && p.Order != "desc") {
		p.Order = "desc"
	}
	return nil
}

// Search request
type SearchRequest struct {
	PaginationRequest
	Search string `json:"search" form:"search" validate:"max=100" example:"john"`
}

func (s *SearchRequest) Validate() error {
	if err := s.PaginationRequest.Validate(); err != nil {
		return err
	}
	s.Search = strings.TrimSpace(s.Search)
	return nil
}

// Login request with validation
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email" example:"user@example.com"`
	Password string `json:"password" validate:"required,min=8" example:"password123"`
	Remember bool   `json:"remember" example:"false"`
}

func (l *LoginRequest) Validate() error {
	if l.Email == "" {
		return errors.New("email is required")
	}
	if !isValidEmail(l.Email) {
		return errors.New("invalid email format")
	}
	if len(l.Password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

// Register request with validation
type RegisterRequest struct {
	FirstName   string `json:"first_name" validate:"required,min=2,max=50" example:"John"`
	LastName    string `json:"last_name" validate:"required,min=2,max=50" example:"Doe"`
	Email       string `json:"email" validate:"required,email" example:"john@example.com"`
	PhoneNumber string `json:"phone_number" validate:"required,e164" example:"+1234567890"`
	Password    string `json:"password" validate:"required,min=8" example:"password123"`
}

func (r *RegisterRequest) Validate() error {
	if r.FirstName == "" || len(r.FirstName) < 2 {
		return errors.New("first name must be at least 2 characters")
	}
	if r.LastName == "" || len(r.LastName) < 2 {
		return errors.New("last name must be at least 2 characters")
	}
	if !isValidEmail(r.Email) {
		return errors.New("invalid email format")
	}
	if len(r.Password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

// Helper function for email validation
func isValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, email)
	return matched
}
