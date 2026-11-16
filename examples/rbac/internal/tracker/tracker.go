// Package tracker is the application's own domain: projects owned by teams,
// tasks inside projects, and invoices owned by organizations. It knows
// nothing about GoAuth; ownership (which organization, which team) is all
// the authorization layer needs from it.
package tracker

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned for an unknown ID.
var ErrNotFound = errors.New("not found")

// Project belongs to one team of one organization.
type Project struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	TeamID    string    `json:"team_id"`
	Name      string    `json:"name"`
	Archived  bool      `json:"archived"`
	CreatedAt time.Time `json:"created_at"`
}

// Task belongs to a project and may be assigned to a user.
type Task struct {
	ID         string `json:"id"`
	ProjectID  string `json:"project_id"`
	Title      string `json:"title"`
	AssigneeID string `json:"assignee_id,omitempty"`
	Done       bool   `json:"done"`
}

// Invoice belongs to an organization. CreatedBy matters for the
// four-eyes rule: nobody approves an invoice they created.
type Invoice struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id"`
	Customer   string     `json:"customer"`
	AmountCent int64      `json:"amount_cents"`
	CreatedBy  string     `json:"created_by"`
	ApprovedBy string     `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
}

// Store keeps the domain in memory. A real application would use its
// database; the shape of the queries is what matters here.
type Store struct {
	mu       sync.RWMutex
	projects map[string]*Project
	tasks    map[string]*Task
	invoices map[string]*Invoice
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{projects: map[string]*Project{}, tasks: map[string]*Task{}, invoices: map[string]*Invoice{}}
}

// --- projects ---

// AddProject stores a project and returns it.
func (s *Store) AddProject(orgID, teamID, name string) *Project {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &Project{ID: uuid.NewString(), OrgID: orgID, TeamID: teamID, Name: name, CreatedAt: time.Now()}
	s.projects[p.ID] = p
	return p
}

// Project returns a copy of a project.
func (s *Store) Project(id string) (Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[id]
	if !ok {
		return Project{}, ErrNotFound
	}
	return *p, nil
}

// ProjectsOfTeams lists the projects of the given teams; nil teams with
// all set lists every project of the organization.
func (s *Store) ProjectsOfTeams(orgID string, teamIDs []string, all bool) []Project {
	s.mu.RLock()
	defer s.mu.RUnlock()
	wanted := map[string]bool{}
	for _, id := range teamIDs {
		wanted[id] = true
	}
	var out []Project
	for _, p := range s.projects {
		if p.OrgID == orgID && (all || wanted[p.TeamID]) {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RenameProject changes a project's name.
func (s *Store) RenameProject(id, name string) (Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[id]
	if !ok {
		return Project{}, ErrNotFound
	}
	p.Name = name
	return *p, nil
}

// ArchiveProject marks a project archived.
func (s *Store) ArchiveProject(id string) (Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[id]
	if !ok {
		return Project{}, ErrNotFound
	}
	p.Archived = true
	return *p, nil
}

// --- tasks ---

// AddTask stores a task.
func (s *Store) AddTask(projectID, title, assigneeID string) *Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &Task{ID: uuid.NewString(), ProjectID: projectID, Title: title, AssigneeID: assigneeID}
	s.tasks[t.ID] = t
	return t
}

// Task returns a copy of a task.
func (s *Store) Task(id string) (Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tasks[id]
	if !ok {
		return Task{}, ErrNotFound
	}
	return *t, nil
}

// CompleteTask marks a task done.
func (s *Store) CompleteTask(id string) (Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return Task{}, ErrNotFound
	}
	t.Done = true
	return *t, nil
}

// --- invoices ---

// AddInvoice stores an invoice.
func (s *Store) AddInvoice(orgID, customer string, amountCents int64, createdBy string) *Invoice {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv := &Invoice{ID: uuid.NewString(), OrgID: orgID, Customer: customer, AmountCent: amountCents, CreatedBy: createdBy}
	s.invoices[inv.ID] = inv
	return inv
}

// Invoice returns a copy of an invoice.
func (s *Store) Invoice(id string) (Invoice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, ok := s.invoices[id]
	if !ok {
		return Invoice{}, ErrNotFound
	}
	return *inv, nil
}

// InvoicesOf lists an organization's invoices.
func (s *Store) InvoicesOf(orgID string) []Invoice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Invoice
	for _, inv := range s.invoices {
		if inv.OrgID == orgID {
			out = append(out, *inv)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Customer < out[j].Customer })
	return out
}

// ApproveInvoice records an approval.
func (s *Store) ApproveInvoice(id, approverID string) (Invoice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invoices[id]
	if !ok {
		return Invoice{}, ErrNotFound
	}
	now := time.Now()
	inv.ApprovedBy, inv.ApprovedAt = approverID, &now
	return *inv, nil
}

// Stats is a platform-wide summary for the report route.
type Stats struct {
	Projects int `json:"projects"`
	Tasks    int `json:"tasks"`
	Invoices int `json:"invoices"`
}

// Stats counts everything, across every organization.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{Projects: len(s.projects), Tasks: len(s.tasks), Invoices: len(s.invoices)}
}
