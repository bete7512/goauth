// Package seed fills a fresh instance with a cast of users, each showing one
// way to hold a permission, plus a little data to try them on.
//
//	Acme Corp (organization, owner alice)
//	├── Engineering        lead: dave
//	│   ├── Backend        erin holds the "developer" role here
//	│   └── Mobile         frank is a plain member; a task is his
//	└── Design
//	Globex (organization, owner gina) ─ Platform
//
// Application-wide: sam is a super admin, sue holds "support".
// Inside Acme: bob is an admin, carol an "accountant", hank "billing".
package seed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"time"

	"github.com/bete7512/goauth/examples/rbac/internal/platform"
	"github.com/bete7512/goauth/examples/rbac/internal/tracker"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/modules/rbac"
	"github.com/google/uuid"
)

// Password is every demo user's password.
const Password = "Tracker-demo-1"

// Person is one demo user and what they are meant to show.
type Person struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	ID    string `json:"id"`
	Shows string `json:"shows"`
}

// Cast is what the seed created, for the walkthrough and the tests.
type Cast struct {
	People map[string]*Person `json:"people"` // by first name, lowercase
	Acme   string             `json:"acme"`   // organization IDs
	Globex string             `json:"globex"`
	Teams  map[string]string  `json:"teams"` // team name → ID
	// Some data to act on: projects, tasks and invoices.
	PaymentsAPI   string `json:"payments_api"`
	IOSApp        string `json:"ios_app"`
	BrandRefresh  string `json:"brand_refresh"`
	GlobexPortal  string `json:"globex_portal"`
	FranksTask    string `json:"franks_task"`
	ErinsTask     string `json:"erins_task"`
	BobsInvoice   string `json:"bobs_invoice"`
	HanksInvoice  string `json:"hanks_invoice"`
	GlobexInvoice string `json:"globex_invoice"`
}

// Run creates the cast. handler serves GoAuth's routes; users sign up
// through it like real users would.
func Run(ctx context.Context, p *platform.Platform, handler http.Handler, store *tracker.Store) (*Cast, error) {
	c := &Cast{People: map[string]*Person{}, Teams: map[string]string{}}
	for _, person := range []Person{
		{Name: "Sam Rivera", Shows: "super admin: everything, everywhere; signs in to the admin console"},
		{Name: "Sue Park", Shows: `"support", application-wide: reads every organization, exports reports`},
		{Name: "Alice Chen", Shows: "owns Acme Corp: everything inside Acme"},
		{Name: "Bob Diaz", Shows: "Acme admin: everything inside Acme, but cannot approve his own invoice"},
		{Name: "Carol Evans", Shows: `"accountant" in Acme: reads and approves invoices`},
		{Name: "Hank Ito", Shows: `"billing" in Acme: creates invoices, cannot approve them`},
		{Name: "Dave Kim", Shows: "lead of Engineering: everything in Engineering, Backend and Mobile"},
		{Name: "Erin Lopez", Shows: `"developer" on Backend: works on Backend's projects only`},
		{Name: "Frank Moss", Shows: "plain member of Mobile: no permissions, but completes his own task"},
		{Name: "Gina Novak", Shows: "owns Globex: nothing inside Acme"},
	} {
		person := person
		person.Email = strings.ToLower(strings.Fields(person.Name)[0]) + "@tracker.test"
		id, err := signup(handler, person.Name, person.Email)
		if err != nil {
			return nil, err
		}
		person.ID = id
		c.People[strings.ToLower(strings.Fields(person.Name)[0])] = &person
	}
	id := func(name string) string { return c.People[name].ID }

	users := p.Store.Core().Users()
	sam, err := users.FindByID(ctx, id("sam"))
	if err != nil {
		return nil, err
	}
	sam.IsSuperAdmin = true
	if err := users.Update(ctx, sam); err != nil {
		return nil, err
	}

	// Organizations and memberships. A real application creates them
	// through POST /auth/org and invitations; the seed writes them directly.
	acme, err := createOrg(ctx, p, "Acme Corp", id("alice"))
	if err != nil {
		return nil, err
	}
	globex, err := createOrg(ctx, p, "Globex", id("gina"))
	if err != nil {
		return nil, err
	}
	c.Acme, c.Globex = acme.org, globex.org
	for name, role := range map[string]string{"bob": "admin", "carol": "member", "hank": "member", "dave": "member", "erin": "member", "frank": "member"} {
		if err := acme.join(ctx, p, id(name), role); err != nil {
			return nil, err
		}
	}

	// The team tree.
	engineering, err := acme.team(ctx, p, "Engineering", nil)
	if err != nil {
		return nil, err
	}
	backend, err := acme.team(ctx, p, "Backend", engineering)
	if err != nil {
		return nil, err
	}
	mobile, err := acme.team(ctx, p, "Mobile", engineering)
	if err != nil {
		return nil, err
	}
	design, err := acme.team(ctx, p, "Design", nil)
	if err != nil {
		return nil, err
	}
	platformTeam, err := globex.team(ctx, p, "Platform", nil)
	if err != nil {
		return nil, err
	}
	for _, t := range []*models.Team{engineering, backend, mobile, design, platformTeam} {
		c.Teams[t.Name] = t.ID
	}
	if err := acme.addToTeam(ctx, p, engineering, id("dave"), models.TeamRoleLead); err != nil {
		return nil, err
	}
	if err := acme.addToTeam(ctx, p, backend, id("erin"), models.TeamRoleMember); err != nil {
		return nil, err
	}
	if err := acme.addToTeam(ctx, p, mobile, id("frank"), models.TeamRoleMember); err != nil {
		return nil, err
	}

	// Roles: application-wide, per organization, per team.
	for _, grant := range []struct {
		user, role string
		where      rbac.Option
	}{
		{"sue", "support", rbac.Global()},
		{"carol", "accountant", rbac.InOrg(acme.org)},
		{"hank", "billing", rbac.InOrg(acme.org)},
		{"erin", "developer", rbac.InTeam(backend.ID)},
	} {
		if err := p.Authz.Assign(ctx, id(grant.user), grant.role, grant.where); err != nil {
			return nil, fmt.Errorf("assign %s to %s: %w", grant.role, grant.user, err)
		}
	}

	// Data.
	c.PaymentsAPI = store.AddProject(acme.org, backend.ID, "Payments API").ID
	c.IOSApp = store.AddProject(acme.org, mobile.ID, "iOS app").ID
	c.BrandRefresh = store.AddProject(acme.org, design.ID, "Brand refresh").ID
	c.GlobexPortal = store.AddProject(globex.org, platformTeam.ID, "Customer portal").ID
	c.ErinsTask = store.AddTask(c.PaymentsAPI, "Retry failed webhooks", id("erin")).ID
	c.FranksTask = store.AddTask(c.IOSApp, "Fix the login screen on iPad", id("frank")).ID
	c.BobsInvoice = store.AddInvoice(acme.org, "Initech", 1_250_00, id("bob")).ID
	c.HanksInvoice = store.AddInvoice(acme.org, "Umbrella", 980_00, id("hank")).ID
	c.GlobexInvoice = store.AddInvoice(globex.org, "Hooli", 4_200_00, id("gina")).ID
	return c, nil
}

// Print writes the cast as a table.
func (c *Cast) Print(w io.Writer) {
	names := make([]string, 0, len(c.People))
	for name := range c.People {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintf(w, "\nDemo users (password %q):\n", Password)
	for _, name := range names {
		p := c.People[name]
		fmt.Fprintf(w, "  %-22s %s\n", p.Email, p.Shows)
	}
	fmt.Fprintf(w, "\nAcme Corp %s\nGlobex    %s\nTeams     ", c.Acme, c.Globex)
	teams := make([]string, 0, len(c.Teams))
	for name, id := range c.Teams {
		teams = append(teams, name+"="+id)
	}
	sort.Strings(teams)
	fmt.Fprintln(w, strings.Join(teams, "\n          "))
	fmt.Fprintf(w, "Projects  payments=%s ios=%s\nInvoices  bob=%s hank=%s\nTasks     frank=%s\n\n",
		c.PaymentsAPI, c.IOSApp, c.BobsInvoice, c.HanksInvoice, c.FranksTask)
}

// --- helpers ---

func signup(handler http.Handler, name, email string) (string, error) {
	body, _ := json.Marshal(map[string]string{"name": name, "email": email, "password": Password})
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		return "", fmt.Errorf("sign up %s: %d %s", email, rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Data.User.ID == "" {
		return "", fmt.Errorf("sign up %s: unexpected response %s", email, rec.Body.String())
	}
	return resp.Data.User.ID, nil
}

type orgSeed struct {
	org         string
	memberships map[string]string // user ID → membership ID
}

func createOrg(ctx context.Context, p *platform.Platform, name, ownerID string) (*orgSeed, error) {
	org := &models.Organization{ID: uuid.NewString(), Name: name, Slug: strings.ToLower(strings.ReplaceAll(name, " ", "-")), OwnerID: ownerID, Active: true, CreatedAt: time.Now()}
	if err := p.Store.Organization().Organizations().Create(ctx, org); err != nil {
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	s := &orgSeed{org: org.ID, memberships: map[string]string{}}
	return s, s.join(ctx, p, ownerID, "owner")
}

func (s *orgSeed) join(ctx context.Context, p *platform.Platform, userID, role string) error {
	member := &models.OrganizationMember{ID: uuid.NewString(), OrgID: s.org, UserID: userID, Role: role, JoinedAt: time.Now()}
	if err := p.Store.Organization().Members().Create(ctx, member); err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	s.memberships[userID] = member.ID
	return nil
}

func (s *orgSeed) team(ctx context.Context, p *platform.Platform, name string, parent *models.Team) (*models.Team, error) {
	t := &models.Team{ID: uuid.NewString(), OrgID: s.org, Name: name, Slug: strings.ToLower(name)}
	parentPath := ""
	if parent != nil {
		t.ParentID, t.Depth, parentPath = parent.ID, parent.Depth+1, parent.Path
	}
	t.Path = models.TeamPath(parentPath, t.ID)
	if err := p.Store.Team().Teams().Create(ctx, t); err != nil {
		return nil, fmt.Errorf("create team %s: %w", name, err)
	}
	return t, nil
}

func (s *orgSeed) addToTeam(ctx context.Context, p *platform.Platform, t *models.Team, userID, role string) error {
	member := &models.TeamMember{TeamID: t.ID, OrgID: s.org, UserID: userID, Role: role, MembershipID: s.memberships[userID]}
	if err := p.Store.Team().Members().Create(ctx, member); err != nil {
		return fmt.Errorf("add %s to %s: %w", userID, t.Name, err)
	}
	return nil
}
