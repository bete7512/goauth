package ui

import (
	"context"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	adminservices "github.com/bete7512/goauth/internal/modules/admin/services"
	coredto "github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	idpdto "github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	orgservices "github.com/bete7512/goauth/internal/modules/organization/services"
	"github.com/bete7512/goauth/internal/modules/rbac/access"
	rbacservices "github.com/bete7512/goauth/internal/modules/rbac/services"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// tab is one entry of a page's tab bar.
type tab struct {
	Label, Href string
	Current     bool
	Count       int
}

// userFrame is what every tab of a user page shows above its content.
type userFrame struct {
	User   *models.User
	Self   bool
	Locked bool
	Tabs   []tab
}

func (m *UIModule) userFrame(r *http.Request, user *models.User, current string) userFrame {
	base := m.base + "/users/" + url.PathEscape(user.ID)
	tabs := []tab{
		{Label: "Profile", Href: base, Current: current == "profile"},
		{Label: "Security", Href: base + "/security", Current: current == "security"},
		{Label: "Access", Href: base + "/access", Current: current == "access"},
	}
	if m.auditService() != nil {
		tabs = append(tabs, tab{Label: "Activity", Href: base + "/activity", Current: current == "activity"})
	}
	return userFrame{
		User:   user,
		Self:   user.ID == visitorFrom(r.Context()).User.ID,
		Locked: user.LockedUntil != nil && user.LockedUntil.After(timeNow()),
		Tabs:   tabs,
	}
}

// loadUser loads the user named in the path, or answers with an error page.
func (m *UIModule) loadUser(w http.ResponseWriter, r *http.Request) (*models.User, bool) {
	user, authErr := m.admin.GetUser(r.Context(), r.PathValue("id"))
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return nil, false
	}
	return user, true
}

// --- create ---

type newUserPage struct {
	Form   adminservices.CreateUserInput
	Policy types.PasswordPolicy
}

func (m *UIModule) newUserPage(w http.ResponseWriter, r *http.Request) {
	page := &newUserPage{Form: adminservices.CreateUserInput{EmailVerified: true}, Policy: m.deps.Config.Security.PasswordPolicy}
	m.render(w, r, http.StatusOK, "user_new", m.newView(r, "New user", "users", page))
}

func (m *UIModule) createUser(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r, m) {
		return
	}
	form := r.PostForm
	input := adminservices.CreateUserInput{
		Email:         strings.TrimSpace(form.Get("email")),
		Name:          strings.TrimSpace(form.Get("name")),
		Username:      strings.TrimSpace(form.Get("username")),
		Password:      form.Get("password"),
		EmailVerified: form.Get("email_verified") == "on",
		SuperAdmin:    form.Get("is_super_admin") == "on",
	}
	user, authErr := m.admin.CreateUser(r.Context(), input)
	if authErr != nil {
		input.Password = ""
		data := m.newView(r, "New user", "users", &newUserPage{Form: input, Policy: m.deps.Config.Security.PasswordPolicy})
		data.Error = authErr.Message
		m.render(w, r, http.StatusUnprocessableEntity, "user_new", data)
		return
	}
	m.redirect(w, r, m.base+"/users/"+url.PathEscape(user.ID)+"?notice=user-created")
}

// --- profile ---

type userPage struct {
	userFrame
	Features features
}

func (m *UIModule) user(w http.ResponseWriter, r *http.Request) {
	user, ok := m.loadUser(w, r)
	if !ok {
		return
	}
	m.showUser(w, r, http.StatusOK, user, "")
}

func (m *UIModule) showUser(w http.ResponseWriter, r *http.Request, status int, user *models.User, message string) {
	page := &userPage{userFrame: m.userFrame(r, user, "profile"), Features: m.features()}
	data := m.newView(r, displayName(user), "users", page)
	data.Error = message
	m.render(w, r, status, "user", data)
}

func (m *UIModule) updateUser(w http.ResponseWriter, r *http.Request) {
	user, ok := m.loadUser(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	form := r.PostForm
	edited := *user
	edited.Name = strings.TrimSpace(form.Get("name"))
	edited.FirstName = strings.TrimSpace(form.Get("first_name"))
	edited.LastName = strings.TrimSpace(form.Get("last_name"))
	edited.Username = strings.TrimSpace(form.Get("username"))
	edited.Email = strings.TrimSpace(form.Get("email"))
	edited.PhoneNumber = strings.TrimSpace(form.Get("phone_number"))
	// An unticked checkbox is not sent, so absence means false.
	edited.Active = form.Get("active") == "on"
	edited.EmailVerified = form.Get("email_verified") == "on"
	edited.PhoneNumberVerified = form.Get("phone_number_verified") == "on"
	edited.IsSuperAdmin = form.Get("is_super_admin") == "on"

	if _, err := mail.ParseAddress(edited.Email); err != nil || !strings.Contains(edited.Email, "@") {
		m.showUser(w, r, http.StatusUnprocessableEntity, &edited, "Enter a valid email address.")
		return
	}
	if user.ID == visitorFrom(r.Context()).User.ID && (!edited.Active || !edited.IsSuperAdmin) {
		m.showUser(w, r, http.StatusUnprocessableEntity, &edited, "You cannot deactivate your own account or remove your own administrator access here.")
		return
	}
	if authErr := m.admin.UpdateUser(r.Context(), &edited); authErr != nil {
		message := authErr.Message
		if authErr.StatusCode >= http.StatusInternalServerError {
			message = "The changes could not be saved. The email or username may already be in use."
		}
		m.showUser(w, r, http.StatusUnprocessableEntity, &edited, message)
		return
	}
	m.redirect(w, r, m.userURL(user.ID, "")+"?notice=saved")
}

func (m *UIModule) deleteUser(w http.ResponseWriter, r *http.Request) {
	user, ok := m.loadUser(w, r)
	if !ok {
		return
	}
	if user.ID == visitorFrom(r.Context()).User.ID {
		m.showUser(w, r, http.StatusUnprocessableEntity, user, "You cannot delete your own account here.")
		return
	}
	if authErr := m.admin.DeleteUser(r.Context(), user.ID); authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	m.redirect(w, r, m.base+"/users?notice=user-deleted")
}

// userAction runs an action on the user in the path and returns to the
// given tab with a notice, or shows the error on the profile page.
func (m *UIModule) userAction(w http.ResponseWriter, r *http.Request, tab, notice string, action func(ctx context.Context, user *models.User) *types.GoAuthError) {
	user, ok := m.loadUser(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	if authErr := action(r.Context(), user); authErr != nil {
		if tab == "security" {
			m.showSecurity(w, r, http.StatusUnprocessableEntity, user, authErr.Message)
			return
		}
		m.showUser(w, r, statusFor(authErr), user, authErr.Message)
		return
	}
	m.redirect(w, r, m.userURL(user.ID, tab)+"?notice="+notice)
}

func (m *UIModule) unlockUser(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "", "unlocked", func(ctx context.Context, user *models.User) *types.GoAuthError {
		return m.admin.Unlock(ctx, user.ID)
	})
}

func (m *UIModule) signOutUser(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "security", "signed-out-user", func(ctx context.Context, user *models.User) *types.GoAuthError {
		if user.ID == visitorFrom(ctx).User.ID {
			return types.NewValidationError("Use Sign out to end your own session.")
		}
		return m.admin.SignOutEverywhere(ctx, user.ID)
	})
}

func (m *UIModule) setUserPassword(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "", "password-set", func(ctx context.Context, user *models.User) *types.GoAuthError {
		if user.ID == visitorFrom(ctx).User.ID {
			return types.NewValidationError("Change your own password from your application's account settings.")
		}
		return m.admin.SetPassword(ctx, user.ID, r.PostForm.Get("password"))
	})
}

func (m *UIModule) sendResetEmail(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "", "reset-sent", func(ctx context.Context, user *models.User) *types.GoAuthError {
		core := m.coreService()
		if core == nil || !m.features().Email {
			return types.NewValidationError("Emails are not enabled. Register the notification module to send them.")
		}
		_, authErr := core.ForgotPassword(ctx, &coredto.ForgotPasswordRequest{Email: user.Email})
		return authErr
	})
}

func (m *UIModule) sendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "", "verification-sent", func(ctx context.Context, user *models.User) *types.GoAuthError {
		core := m.coreService()
		if core == nil || !m.features().Email {
			return types.NewValidationError("Emails are not enabled. Register the notification module to send them.")
		}
		if user.EmailVerified {
			return types.NewValidationError("This email address is already verified.")
		}
		_, authErr := core.SendEmailVerification(ctx, user.Email)
		return authErr
	})
}

// --- security ---

type securityPage struct {
	userFrame
	Features features
	Security *adminservices.UserSecurity
	Apps     []idpdto.Grant
}

func (m *UIModule) userSecurity(w http.ResponseWriter, r *http.Request) {
	user, ok := m.loadUser(w, r)
	if !ok {
		return
	}
	m.showSecurity(w, r, http.StatusOK, user, "")
}

func (m *UIModule) showSecurity(w http.ResponseWriter, r *http.Request, status int, user *models.User, message string) {
	security, authErr := m.admin.Security(r.Context(), user.ID)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &securityPage{userFrame: m.userFrame(r, user, "security"), Features: m.features(), Security: security}
	if idp := m.idpService(); idp != nil {
		opts := models.IDPGrantListOpts{ListingOpts: models.ListingOpts{Limit: 100}}
		opts.Normalize(100)
		if grants, _, authErr := idp.ListGrants(r.Context(), user.ID, opts); authErr == nil {
			page.Apps = grants
		}
	}
	data := m.newView(r, displayName(user), "users", page)
	data.Error = message
	m.render(w, r, status, "user_security", data)
}

func (m *UIModule) unlinkAccount(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "security", "account-unlinked", func(ctx context.Context, user *models.User) *types.GoAuthError {
		return m.admin.UnlinkAccount(ctx, user.ID, r.PathValue("accountId"))
	})
}

func (m *UIModule) revokeSession(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "security", "session-revoked", func(ctx context.Context, user *models.User) *types.GoAuthError {
		return m.admin.RevokeSession(ctx, user.ID, r.PathValue("sessionId"))
	})
}

func (m *UIModule) resetTwoFactor(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "security", "2fa-reset", func(ctx context.Context, user *models.User) *types.GoAuthError {
		return m.admin.ResetTwoFactor(ctx, user.ID)
	})
}

func (m *UIModule) deletePasskey(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "security", "passkey-deleted", func(ctx context.Context, user *models.User) *types.GoAuthError {
		return m.admin.DeletePasskey(ctx, user.ID, r.PathValue("passkeyId"))
	})
}

func (m *UIModule) revokeApp(w http.ResponseWriter, r *http.Request) {
	m.userAction(w, r, "security", "app-revoked", func(ctx context.Context, user *models.User) *types.GoAuthError {
		idp := m.idpService()
		if idp == nil {
			return types.NewValidationError("The identity provider is not enabled.")
		}
		return idp.RevokeGrant(ctx, user.ID, r.PathValue("grantId"), metadata(r))
	})
}

// --- access ---

type accessPage struct {
	userFrame
	Roles       *rbacRoles
	Memberships []orgservices.AdminMembership
	OrgsEnabled bool
}

// rbacRoles is a roles section: what can be assigned and what is held.
type rbacRoles struct {
	Assignable []*rbacservices.RoleView
	Held       []string // keys of the roles assigned
	Implied    []string // names of roles from the super admin flag or membership
	Grants     []string
	Error      string
	Action     string // where the form posts
}

func (m *UIModule) userAccess(w http.ResponseWriter, r *http.Request) {
	user, ok := m.loadUser(w, r)
	if !ok {
		return
	}
	m.showAccess(w, r, http.StatusOK, user, "")
}

func (m *UIModule) showAccess(w http.ResponseWriter, r *http.Request, status int, user *models.User, message string) {
	page := &accessPage{userFrame: m.userFrame(r, user, "access")}
	if _, internals, ok := m.rbacModule(); ok {
		page.Roles = m.heldRoles(r, internals, user.ID, access.GlobalScope())
		page.Roles.Action = m.userURL(user.ID, "roles")
	}
	if orgs := m.orgAdmin(); orgs != nil {
		page.OrgsEnabled = true
		if memberships, authErr := orgs.ListUserMemberships(r.Context(), user.ID); authErr == nil {
			page.Memberships = memberships
		}
	}
	data := m.newView(r, displayName(user), "users", page)
	data.Error = message
	m.render(w, r, status, "user_access", data)
}

// heldRoles builds a roles section for a user in a scope.
func (m *UIModule) heldRoles(r *http.Request, internals rbacInternals, userID string, scope access.Scope) *rbacRoles {
	section := &rbacRoles{}
	opts := models.RoleListOpts{ListingOpts: models.ListingOpts{Limit: 100, SortField: "name", SortDir: "asc"}}
	opts.Normalize(100)
	roles, _, authErr := internals.Roles.List(r.Context(), m.actor(r), scope, opts)
	if authErr != nil {
		section.Error = authErr.Message
		return section
	}
	for _, role := range roles {
		if !role.Implied {
			section.Assignable = append(section.Assignable, role)
		}
	}
	held, authErr := internals.Assignments.Get(r.Context(), m.actor(r), userID, scope)
	if authErr != nil {
		section.Error = authErr.Message
		return section
	}
	for _, role := range held.Roles {
		switch {
		case role.Implied:
			section.Implied = append(section.Implied, role.Name)
		case role.Scope == scope.Type:
			section.Held = append(section.Held, role.Key)
		}
	}
	section.Grants = held.Grants
	return section
}

func (m *UIModule) setUserRoles(w http.ResponseWriter, r *http.Request) {
	user, ok := m.loadUser(w, r)
	if !ok || !parseForm(w, r, m) {
		return
	}
	_, internals, enabled := m.rbacModule()
	if !enabled {
		m.unavailable(w, r, "Roles", "rbac")
		return
	}
	if _, authErr := internals.Assignments.Set(r.Context(), m.actor(r), user.ID, access.GlobalScope(), r.PostForm["roles"]); authErr != nil {
		m.showAccess(w, r, http.StatusUnprocessableEntity, user, authErr.Message)
		return
	}
	m.redirect(w, r, m.userURL(user.ID, "access")+"?notice=roles-saved")
}

// --- activity ---

type activityPage struct {
	userFrame
	Events []*models.AuditLog
	Pager  pager
}

func (m *UIModule) userActivity(w http.ResponseWriter, r *http.Request) {
	user, ok := m.loadUser(w, r)
	if !ok {
		return
	}
	auditService := m.auditService()
	if auditService == nil {
		m.unavailable(w, r, "Activity records", "audit")
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	opts := models.AuditLogListOpts{ListingOpts: models.ListingOpts{Offset: offset, Limit: m.config.PageSize, SortField: "created_at", SortDir: "desc"}}
	opts.Normalize(m.config.PageSize)
	events, total, authErr := auditService.GetUserAuditLogs(r.Context(), user.ID, opts)
	if authErr != nil {
		m.serviceError(w, r, authErr)
		return
	}
	page := &activityPage{userFrame: m.userFrame(r, user, "activity"), Events: events,
		Pager: pager{Offset: opts.Offset, Limit: opts.Limit, Total: total, Path: m.userURL(user.ID, "activity"), Target: "activity-list"}}
	m.render(w, r, http.StatusOK, "user_activity", m.newView(r, displayName(user), "users", page), "activity-list")
}

// --- helpers ---

func (m *UIModule) userURL(userID, tab string) string {
	link := m.base + "/users/" + url.PathEscape(userID)
	if tab != "" {
		link += "/" + tab
	}
	return link
}

// parseForm reads a posted form or answers with an error page.
func parseForm(w http.ResponseWriter, r *http.Request, m *UIModule) bool {
	if err := r.ParseForm(); err != nil {
		m.renderError(w, r, http.StatusBadRequest, "The form could not be read.")
		return false
	}
	return true
}

func statusFor(authErr *types.GoAuthError) int {
	if authErr.StatusCode >= http.StatusBadRequest && authErr.StatusCode < http.StatusInternalServerError {
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}
