package ui

import (
	"net/http"
	"strings"

	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	idpdto "github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/passkeys"
	passkeydto "github.com/bete7512/goauth/internal/modules/passkeys/handlers/dto"
	passkeyservices "github.com/bete7512/goauth/internal/modules/passkeys/services"
	"github.com/bete7512/goauth/internal/modules/session"
	sessiondto "github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	sessionservices "github.com/bete7512/goauth/internal/modules/session/services"
	http_utils "github.com/bete7512/goauth/internal/utils/http"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// The account page is the signed-in user's own: profile, password, where
// they are signed in, passkeys and connected applications. Every change goes
// through the owning module's self-service operation, the same one its JSON
// route uses, so the rules (password policy, ownership checks, events) are
// the same.

type accountPage struct {
	User      *models.User
	Events    []*models.AuditLog
	Policy    types.PasswordPolicy
	Sessions  []sessiondto.SessionDTO
	Passkeys  []*passkeydto.PasskeySummary
	Apps      []idpdto.Grant
	TwoFactor *models.TwoFactor
	Linked    []*models.Account
	// HasPassword is false for an account created through a linked
	// identity, which has no password to change.
	HasPassword bool
}

// accountOnly serves the account pages to administrators always and to
// everyone else only with Config.UserPages. Without UserPages a non-admin
// may still hold the application's cookies, which reach the console path.
func (m *UIModule) accountOnly(next http.HandlerFunc) http.HandlerFunc {
	return m.signedIn(func(w http.ResponseWriter, r *http.Request) {
		if !m.config.UserPages && !visitorFrom(r.Context()).admin() {
			m.renderError(w, r, http.StatusForbidden, "This console is for administrators.")
			return
		}
		next(w, r)
	})
}

func (m *UIModule) account(w http.ResponseWriter, r *http.Request) {
	m.showAccount(w, r, http.StatusOK, visitorFrom(r.Context()).User, "")
}

func (m *UIModule) showAccount(w http.ResponseWriter, r *http.Request, status int, user *models.User, message string) {
	v := visitorFrom(r.Context())
	ctx := r.Context()
	page := &accountPage{User: user, Policy: m.deps.Config.Security.PasswordPolicy, HasPassword: v.User.PasswordHash != ""}
	if auditService := m.auditService(); auditService != nil {
		opts := models.AuditLogListOpts{ListingOpts: models.ListingOpts{Limit: 10, SortField: "created_at", SortDir: "desc"}}
		opts.Normalize(10)
		if events, _, authErr := auditService.GetMyAuditLogs(ctx, v.User.ID, opts); authErr == nil {
			page.Events = events
		}
	}
	if sessions := m.sessionService(); sessions != nil {
		opts := models.SessionListOpts{ListingOpts: models.ListingOpts{Limit: 50, SortField: "created_at", SortDir: "desc"}}
		opts.Normalize(50)
		if list, _, authErr := sessions.ListSessions(ctx, v.User.ID, v.Principal.SessionID, opts); authErr == nil {
			page.Sessions = list
		}
	}
	if passkeyService := m.passkeyService(); passkeyService != nil {
		if list, authErr := passkeyService.ListCredentials(ctx, v.User.ID); authErr == nil {
			page.Passkeys = list
		}
	}
	if idp := m.idpService(); idp != nil {
		opts := models.IDPGrantListOpts{ListingOpts: models.ListingOpts{Limit: 100}}
		opts.Normalize(100)
		if grants, _, authErr := idp.ListGrants(ctx, v.User.ID, opts); authErr == nil {
			page.Apps = grants
		}
	}
	f := m.features()
	if store := m.deps.Storage.TwoFactorAuth(); f.TwoFactor && store != nil {
		if config, err := store.TwoFactor().GetByUserID(ctx, v.User.ID); err == nil && config != nil {
			page.TwoFactor = config
		}
	}
	if store := m.deps.Storage.OAuth(); f.LinkedAccount && store != nil {
		if accounts, err := store.Accounts().FindByUserID(ctx, v.User.ID); err == nil {
			page.Linked = accounts
		}
	}
	data := m.newView(r, "Your account", "account", page)
	data.Error = message
	m.render(w, r, status, "account", data)
}

// updateAccount saves the profile fields a user may change themselves.
func (m *UIModule) updateAccount(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r, m) {
		return
	}
	v := visitorFrom(r.Context())
	edited := *v.User
	request := &dto.UpdateProfileRequest{
		Name:  strings.TrimSpace(r.PostForm.Get("name")),
		Phone: strings.TrimSpace(r.PostForm.Get("phone_number")),
	}
	edited.Name, edited.PhoneNumber = request.Name, request.Phone
	if err := request.Validate(); err != nil {
		m.showAccount(w, r, http.StatusUnprocessableEntity, &edited, "Enter a valid phone number, in international format such as +14155550100.")
		return
	}
	core := m.coreService()
	if core == nil {
		m.renderError(w, r, http.StatusServiceUnavailable, "Profile changes are unavailable.")
		return
	}
	if _, authErr := core.UpdateProfile(r.Context(), v.User.ID, request); authErr != nil {
		m.showAccount(w, r, statusFor(authErr), &edited, authErr.Message)
		return
	}
	if request.Phone != "" && request.Phone != v.User.PhoneNumber {
		// A new phone number may be a sign-in factor, so core ends every
		// sign-in when it changes; this one is gone too.
		m.endSignIn(w, r, v)
		m.redirect(w, r, m.base+"/login?notice=phone-changed")
		return
	}
	m.redirect(w, r, m.base+"/account?notice=saved")
}

// changePassword checks the current password and sets a new one. Changing a
// password ends every sign-in, this one included, so the user signs in again
// with the new password.
func (m *UIModule) changePassword(w http.ResponseWriter, r *http.Request) {
	if !parseForm(w, r, m) {
		return
	}
	v := visitorFrom(r.Context())
	current, next, confirm := r.PostForm.Get("current_password"), r.PostForm.Get("new_password"), r.PostForm.Get("confirm_password")
	switch {
	case current == "" || next == "":
		m.showAccount(w, r, http.StatusUnprocessableEntity, v.User, "Enter your current password and a new one.")
		return
	case next != confirm:
		m.showAccount(w, r, http.StatusUnprocessableEntity, v.User, "The new passwords do not match.")
		return
	case next == current:
		m.showAccount(w, r, http.StatusUnprocessableEntity, v.User, "Choose a password different from the current one.")
		return
	}
	core := m.coreService()
	if core == nil {
		m.renderError(w, r, http.StatusServiceUnavailable, "Password changes are unavailable.")
		return
	}
	if _, authErr := core.ChangePassword(r.Context(), v.User.ID, &dto.ChangePasswordRequest{OldPassword: current, NewPassword: next}); authErr != nil {
		message := authErr.Message
		if authErr.Code == types.ErrInvalidCredentials {
			message = "Your current password is incorrect."
		}
		m.showAccount(w, r, statusFor(authErr), v.User, message)
		return
	}
	m.endSignIn(w, r, v)
	m.redirect(w, r, m.base+"/login?notice=password-changed")
}

// endSignIn ends the visitor's sign-in after a change that already
// invalidated their tokens, so that no session row or cookie is left behind.
func (m *UIModule) endSignIn(w http.ResponseWriter, r *http.Request, v *visitor) {
	if revoker, ok := m.strategy().(types.CredentialRevoker); ok {
		_ = revoker.SignOut(r.Context(), v.Principal)
	}
	http_utils.ClearCredentialCookies(w, m.deps.Config.Security)
}

func (m *UIModule) revokeOwnSession(w http.ResponseWriter, r *http.Request) {
	v := visitorFrom(r.Context())
	sessions := m.sessionService()
	if sessions == nil {
		m.renderError(w, r, http.StatusNotFound, "This application does not keep a list of sessions.")
		return
	}
	id := r.PathValue("sessionId")
	if id == v.Principal.SessionID {
		m.showAccount(w, r, http.StatusUnprocessableEntity, v.User, "Use Sign out to end this session.")
		return
	}
	if authErr := sessions.DeleteSession(r.Context(), v.User.ID, id); authErr != nil {
		m.showAccount(w, r, statusFor(authErr), v.User, authErr.Message)
		return
	}
	m.redirect(w, r, m.base+"/account?notice=session-revoked")
}

func (m *UIModule) deleteOwnPasskey(w http.ResponseWriter, r *http.Request) {
	v := visitorFrom(r.Context())
	passkeyService := m.passkeyService()
	if passkeyService == nil {
		m.unavailable(w, r, "Passkeys", "passkeys")
		return
	}
	if authErr := passkeyService.DeleteCredential(r.Context(), v.User.ID, r.PathValue("passkeyId")); authErr != nil {
		m.showAccount(w, r, statusFor(authErr), v.User, authErr.Message)
		return
	}
	m.redirect(w, r, m.base+"/account?notice=passkey-deleted")
}

func (m *UIModule) revokeOwnApp(w http.ResponseWriter, r *http.Request) {
	v := visitorFrom(r.Context())
	idp := m.idpService()
	if idp == nil {
		m.unavailable(w, r, "Connected applications", "idp")
		return
	}
	if authErr := idp.RevokeGrant(r.Context(), v.User.ID, r.PathValue("grantId"), metadata(r)); authErr != nil {
		m.showAccount(w, r, statusFor(authErr), v.User, authErr.Message)
		return
	}
	m.redirect(w, r, m.base+"/account?notice=app-revoked")
}

// --- collaborators ---

// sessionService returns the session module's service when the session
// strategy is in use.
func (m *UIModule) sessionService() sessionservices.SessionService {
	if m.deps.Config.Security.AuthStrategy != types.StrategySession {
		return nil
	}
	module, ok := lookup[*session.SessionModule](m, types.SessionModule)
	if !ok {
		return nil
	}
	return session.ServiceOf(module)
}

func (m *UIModule) passkeyService() passkeyservices.PasskeyService {
	module, ok := lookup[*passkeys.PasskeysModule](m, types.PasskeysModule)
	if !ok {
		return nil
	}
	return passkeys.ServiceOf(module)
}
