package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/modules/idp/handlers/dto"
	"github.com/bete7512/goauth/internal/oauthproto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

const (
	// maxStateLength bounds the client's opaque state, which is stored with
	// the pending request and echoed in the redirect.
	maxStateLength = 2048
	// maxNonceLength bounds the nonce, which is stored and copied into the ID token.
	maxNonceLength = 512
	// maxLoginHintLength is the longest email address (RFC 5321).
	maxLoginHintLength = 320
	// maxAgeLimit bounds max_age so it cannot overflow a duration.
	maxAgeLimit = 10 * 365 * 24 * 60 * 60
)

// pendingAuthorization is the stored state of an authorization request that
// waits for the user's decision.
type pendingAuthorization struct {
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	State         string   `json:"state,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	CodeChallenge string   `json:"code_challenge,omitempty"`
	Scopes        []string `json:"scopes"`
	// RequireLogin is set by prompt=login: the user must have signed in
	// after the request was made.
	RequireLogin bool `json:"require_login,omitempty"`
	// ForceConsent is set by prompt=consent: remembered consent is not enough.
	ForceConsent bool `json:"force_consent,omitempty"`
	// MaxAge is max_age in seconds: how long ago the user may have signed in.
	MaxAge    *int64 `json:"max_age,omitempty"`
	LoginHint string `json:"login_hint,omitempty"`
}

// authorizationCode is the stored state behind an authorization code. It
// carries everything the token endpoint needs, fixed at the moment the user
// approved.
type authorizationCode struct {
	GrantID       string   `json:"grant_id"`
	ClientID      string   `json:"client_id"`
	UserID        string   `json:"user_id"`
	RedirectURI   string   `json:"redirect_uri"`
	CodeChallenge string   `json:"code_challenge,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	Scopes        []string `json:"scopes"`
	// AuthTime is when the user signed in, in Unix seconds; 0 when unknown.
	AuthTime int64    `json:"auth_time,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	// Binding identifies the user's password as it was at approval.
	Binding string `json:"binding"`
}

// single returns the value of a parameter that may appear at most once
// (RFC 6749 section 3.1). ok is false when it is repeated.
func single(values url.Values, name string) (string, bool) {
	switch list := values[name]; len(list) {
	case 0:
		return "", true
	case 1:
		return list[0], true
	}
	return "", false
}

// Authorize validates an authentication request (OpenID Connect Core section
// 3.1.2.1). Problems with the client or its redirect URI are returned as an
// error, because the user must not be sent to an unverified location. Every
// other problem is returned to the client as a redirect.
func (s *idpService) Authorize(ctx context.Context, query url.Values) (string, *types.GoAuthError) {
	clientID, ok := single(query, "client_id")
	if !ok || clientID == "" {
		return "", errInvalidRequest("client_id is required")
	}
	client, authErr := s.resolveClient(ctx, clientID)
	if authErr != nil {
		if authErr.Code == CodeInvalidClient {
			return "", oauthError(CodeInvalidClient, http.StatusBadRequest, "Unknown client")
		}
		return "", authErr
	}
	redirectURI, ok := single(query, "redirect_uri")
	if !ok || redirectURI == "" {
		return "", errInvalidRequest("redirect_uri is required")
	}
	if !oauthproto.MatchRedirectURI(client.RedirectURIs, redirectURI) {
		return "", errInvalidRequest("redirect_uri is not registered for this client")
	}

	// The redirect URI is verified: from here on errors go back to the client.
	state, stateOK := single(query, "state")
	if !stateOK || len(state) > maxStateLength {
		state = ""
	}
	fail := func(code types.ErrorCode, description string) (string, *types.GoAuthError) {
		return s.authorizationError(redirectURI, state, code, description)
	}
	if !stateOK || len(query.Get("state")) > maxStateLength {
		return fail(CodeInvalidRequest, "state is repeated or too long")
	}
	for _, name := range []string{"response_type", "response_mode", "scope", "nonce", "code_challenge", "code_challenge_method", "prompt", "max_age", "login_hint"} {
		if _, ok := single(query, name); !ok {
			return fail(CodeInvalidRequest, name+" must not be repeated")
		}
	}
	if query.Has("request") {
		return fail(CodeRequestNotSupported, "Request objects are not supported")
	}
	if query.Has("request_uri") {
		return fail(CodeRequestURINotSupported, "Request objects are not supported")
	}
	if query.Get("response_type") != "code" {
		return fail(CodeUnsupportedResponseType, "Only the code response type is supported")
	}
	if mode := query.Get("response_mode"); mode != "" && mode != "query" {
		return fail(CodeInvalidRequest, "Only the query response mode is supported")
	}

	requested, err := oauthproto.ParseScope(query.Get("scope"))
	if err != nil {
		return fail(CodeInvalidScope, "The scope parameter is malformed")
	}
	if !hasScope(requested, ScopeOpenID) {
		return fail(CodeInvalidScope, "The openid scope is required")
	}
	// Scopes the client is not registered for, or that mean nothing here,
	// are left out rather than refused (OpenID Connect Core section 3.1.2.1).
	// The token response states what was granted.
	scopes := make([]string, 0, len(requested))
	for _, scope := range requested {
		if supportedScope(scope) && client.Scopes.Contains(scope) {
			scopes = append(scopes, scope)
		}
	}
	if !hasScope(scopes, ScopeOpenID) {
		return fail(CodeInvalidScope, "The client is not registered for the openid scope")
	}

	challenge := query.Get("code_challenge")
	switch {
	case challenge != "":
		if query.Get("code_challenge_method") != "S256" || !oauthproto.ValidCodeChallenge(challenge) {
			return fail(CodeInvalidRequest, "PKCE must use code_challenge_method=S256 with a 43-character challenge")
		}
	case query.Get("code_challenge_method") != "":
		return fail(CodeInvalidRequest, "code_challenge_method was sent without code_challenge")
	case client.RequirePKCE:
		return fail(CodeInvalidRequest, "PKCE is required: send code_challenge with code_challenge_method=S256")
	}

	nonce := query.Get("nonce")
	if len(nonce) > maxNonceLength {
		return fail(CodeInvalidRequest, "nonce is too long")
	}
	loginHint := query.Get("login_hint")
	if len(loginHint) > maxLoginHintLength {
		loginHint = ""
	}

	pending := pendingAuthorization{
		ClientID: client.ClientID, RedirectURI: redirectURI, State: state, Nonce: nonce,
		CodeChallenge: challenge, Scopes: scopes, LoginHint: loginHint,
	}
	prompts := strings.Fields(query.Get("prompt"))
	for _, prompt := range prompts {
		switch prompt {
		case "none":
			if len(prompts) > 1 {
				return fail(CodeInvalidRequest, "prompt=none cannot be combined with another value")
			}
			// Whether the user is signed in is known to the host's
			// frontend, not to this endpoint, so a request that forbids
			// showing a page cannot be answered.
			return fail(CodeInteractionRequired, "Sign-in without user interaction (prompt=none) is not supported")
		case "login":
			pending.RequireLogin = true
		case "consent":
			pending.ForceConsent = true
		case "select_account":
			// There is one account per browser session; nothing to choose.
		default:
			return fail(CodeInvalidRequest, "Unsupported prompt value")
		}
	}
	if raw := query.Get("max_age"); raw != "" {
		maxAge, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || maxAge < 0 {
			return fail(CodeInvalidRequest, "max_age must be a non-negative number of seconds")
		}
		if maxAge > maxAgeLimit {
			maxAge = maxAgeLimit
		}
		pending.MaxAge = &maxAge
	}

	requestID, err := randomToken(24)
	if err != nil {
		return fail(CodeServerError, "")
	}
	data, err := json.Marshal(pending)
	if err != nil {
		return fail(CodeServerError, "")
	}
	now := s.now()
	// The record names no user: nobody has decided yet.
	record := &models.Token{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Type:      models.TokenTypeIDPRequest,
		Token:     security.TokenDigest(requestID),
		Data:      string(data),
		ExpiresAt: now.Add(s.settings.RequestTTL),
		CreatedAt: now,
	}
	if err := s.stores.Tokens.Create(ctx, record); err != nil {
		s.logger.Errorf("idp: failed to store authorization request: %v", err)
		return fail(CodeServerError, "")
	}
	consentURL, err := oauthproto.AppendQuery(s.settings.ConsentURL, url.Values{"request_id": {requestID}})
	if err != nil {
		return fail(CodeServerError, "")
	}
	return consentURL, nil
}

// authorizationError builds the error redirect of RFC 6749 section 4.1.2.1,
// with the issuer identifier of RFC 9207.
func (s *idpService) authorizationError(redirectURI, state string, code types.ErrorCode, description string) (string, *types.GoAuthError) {
	params := url.Values{"error": {string(code)}, "iss": {s.settings.Issuer}}
	if description != "" {
		params.Set("error_description", description)
	}
	if state != "" {
		params.Set("state", state)
	}
	target, err := oauthproto.AppendQuery(redirectURI, params)
	if err != nil {
		return "", errServer(err)
	}
	return target, nil
}

// loadPending finds an undecided, unexpired authorization request.
func (s *idpService) loadPending(ctx context.Context, requestID string) (*models.Token, *pendingAuthorization, *types.GoAuthError) {
	if requestID == "" || len(requestID) > 128 {
		return nil, nil, types.NewIDPRequestNotFoundError()
	}
	record, err := s.stores.Tokens.FindByToken(ctx, security.TokenDigest(requestID))
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, nil, types.NewIDPRequestNotFoundError()
		}
		return nil, nil, types.NewInternalError("failed to load sign-in request").Wrap(err)
	}
	if record.Type != models.TokenTypeIDPRequest || record.Used || expired(record.ExpiresAt, s.now()) {
		return nil, nil, types.NewIDPRequestNotFoundError()
	}
	var pending pendingAuthorization
	if err := json.Unmarshal([]byte(record.Data), &pending); err != nil || pending.ClientID == "" || pending.RedirectURI == "" {
		return nil, nil, types.NewIDPRequestNotFoundError()
	}
	return record, &pending, nil
}

// pendingClient loads the client of a pending request. It may have been
// removed or disabled since the request was made.
func (s *idpService) pendingClient(ctx context.Context, pending *pendingAuthorization) (*models.IDPClient, *types.GoAuthError) {
	client, authErr := s.resolveClient(ctx, pending.ClientID)
	if authErr != nil {
		if authErr.Code == CodeInvalidClient {
			return nil, types.NewIDPRequestNotFoundError()
		}
		return nil, types.NewInternalError("failed to load the client application").Wrap(authErr)
	}
	return client, nil
}

// existingGrant returns the grant the user gave the client, or nil.
func (s *idpService) existingGrant(ctx context.Context, userID, clientID string) (*models.IDPGrant, *types.GoAuthError) {
	grant, err := s.stores.Grants.FindByUserAndClient(ctx, userID, clientID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, nil
		}
		return nil, types.NewInternalError("failed to load grant").Wrap(err)
	}
	return grant, nil
}

// loginStale reports whether the user's sign-in is too old for the request:
// prompt=login wants one made after the request, max_age one no older than
// that many seconds. A sign-in whose time is unknown satisfies neither.
func loginStale(pending *pendingAuthorization, requestedAt time.Time, principal types.Principal, now time.Time) bool {
	if !pending.RequireLogin && pending.MaxAge == nil {
		return false
	}
	authTime := principal.AuthenticatedAt
	if authTime.IsZero() {
		return true
	}
	// Sign-in times are kept in whole seconds.
	if pending.RequireLogin && authTime.Unix() < requestedAt.Unix() {
		return true
	}
	if pending.MaxAge != nil && now.Unix()-authTime.Unix() > *pending.MaxAge {
		return true
	}
	return false
}

// consentRequired reports whether the user has to be asked: not for an
// application the host operates itself, and otherwise whenever the request
// insists or asks for more than the user approved before.
func consentRequired(client *models.IDPClient, pending *pendingAuthorization, grant *models.IDPGrant) bool {
	if client.SkipConsent {
		return false
	}
	if pending.ForceConsent || grant == nil {
		return true
	}
	return !oauthproto.ScopeSubset(pending.Scopes, grant.Scopes)
}

// ConsentDetails describes a pending request to the signed-in user.
func (s *idpService) ConsentDetails(ctx context.Context, principal types.Principal, requestID string) (*dto.ConsentDetails, *types.GoAuthError) {
	record, pending, authErr := s.loadPending(ctx, requestID)
	if authErr != nil {
		return nil, authErr
	}
	client, authErr := s.pendingClient(ctx, pending)
	if authErr != nil {
		return nil, authErr
	}
	grant, authErr := s.existingGrant(ctx, principal.UserID, client.ClientID)
	if authErr != nil {
		return nil, authErr
	}

	details := &dto.ConsentDetails{
		RequestID: requestID,
		Client: dto.ConsentClient{
			ClientID: client.ClientID, Name: client.Name, LogoURI: client.LogoURI, ClientURI: client.ClientURI,
		},
		RedirectHost:    oauthproto.RedirectHost(pending.RedirectURI),
		Scopes:          make([]dto.ConsentScope, 0, len(pending.Scopes)),
		ConsentRequired: consentRequired(client, pending, grant),
		LoginRequired:   loginStale(pending, record.CreatedAt, principal, s.now()),
		LoginHint:       pending.LoginHint,
		ExpiresAt:       record.ExpiresAt,
	}
	for _, name := range pending.Scopes {
		details.Scopes = append(details.Scopes, dto.ConsentScope{
			Name: name, Description: scopeDescriptions[name],
			PreviouslyGranted: grant != nil && grant.Scopes.Contains(name),
		})
	}
	return details, nil
}

// ApproveConsent records the user's approval: it stores the grant and an
// authorization code in one transaction and returns the client redirect.
func (s *idpService) ApproveConsent(ctx context.Context, principal types.Principal, requestID string, metadata *types.RequestMetadata) (string, *types.GoAuthError) {
	record, pending, authErr := s.loadPending(ctx, requestID)
	if authErr != nil {
		return "", authErr
	}
	client, authErr := s.pendingClient(ctx, pending)
	if authErr != nil {
		return "", authErr
	}
	user, err := s.stores.Users.FindByID(ctx, principal.UserID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return "", types.NewUnauthorizedError()
		}
		return "", types.NewInternalError("failed to load user").Wrap(err)
	}
	if eligibility := security.CheckEligibility(user, s.deps.Config.Core); eligibility != nil {
		return "", eligibility
	}
	now := s.now()
	// The request stays open: the page signs the user in again and retries.
	if loginStale(pending, record.CreatedAt, principal, now) {
		return "", types.NewIDPLoginRequiredError()
	}

	code, err := randomToken(32)
	if err != nil {
		return "", types.NewInternalError("failed to generate authorization code").Wrap(err)
	}
	stored := authorizationCode{
		ClientID: client.ClientID, UserID: user.ID, RedirectURI: pending.RedirectURI,
		CodeChallenge: pending.CodeChallenge, Nonce: pending.Nonce, Scopes: pending.Scopes,
		AMR: principal.Methods, Binding: credentialBinding(user),
	}
	if !principal.AuthenticatedAt.IsZero() {
		stored.AuthTime = principal.AuthenticatedAt.Unix()
	}
	event := &types.IDPEventData{
		UserID: user.ID, ActorID: user.ID, ClientID: client.ClientID, ClientName: client.Name, Scopes: pending.Scopes,
		TargetType: "idp_grant", Details: "Signed in to client application " + client.Name,
	}
	if metadata != nil {
		event.IP, event.UserAgent = metadata.IPAddress, metadata.UserAgent
	}

	authErr = s.atomically(ctx, func(tx *idpService) *types.GoAuthError {
		// Consuming the request first makes the decision single use.
		if err := tx.stores.Tokens.MarkAsUsed(ctx, record.ID); err != nil {
			if errors.Is(err, models.ErrConflict) {
				return types.NewIDPRequestNotFoundError()
			}
			return types.NewInternalError("failed to consume sign-in request").Wrap(err)
		}
		grant, authErr := tx.recordGrant(ctx, user.ID, client.ClientID, pending.Scopes, now)
		if authErr != nil {
			return authErr
		}
		stored.GrantID = grant.ID
		codeData, err := json.Marshal(stored)
		if err != nil {
			return types.NewInternalError("failed to encode authorization code").Wrap(err)
		}
		// The record names no user: the grant does. Flows that clear a
		// user's own token records, such as signing out, leave it alone.
		if err := tx.stores.Tokens.Create(ctx, &models.Token{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Type:      models.TokenTypeIDPCode,
			Token:     security.TokenDigest(code),
			Data:      string(codeData),
			ExpiresAt: now.Add(tx.settings.CodeTTL),
			CreatedAt: now,
		}); err != nil {
			return types.NewInternalError("failed to store authorization code").Wrap(err)
		}
		event.GrantID, event.TargetID = grant.ID, grant.ID
		tx.emit(ctx, types.EventIDPConsentGranted, event)
		return nil
	})
	if authErr != nil {
		return "", authErr
	}

	params := url.Values{"code": {code}, "iss": {s.settings.Issuer}}
	if pending.State != "" {
		params.Set("state", pending.State)
	}
	target, err := oauthproto.AppendQuery(pending.RedirectURI, params)
	if err != nil {
		return "", types.NewInternalError("failed to build redirect").Wrap(err)
	}
	return target, nil
}

// recordGrant stores what the user approved: a new grant, or the union of
// the scopes approved before and now.
func (s *idpService) recordGrant(ctx context.Context, userID, clientID string, scopes []string, now time.Time) (*models.IDPGrant, *types.GoAuthError) {
	// Two attempts: a concurrent approval may create the grant between the
	// lookup and the insert.
	for attempt := 0; attempt < 2; attempt++ {
		grant, authErr := s.existingGrant(ctx, userID, clientID)
		if authErr != nil {
			return nil, authErr
		}
		if grant == nil {
			grant = &models.IDPGrant{
				ID: uuid.Must(uuid.NewV7()).String(), UserID: userID, ClientID: clientID,
				Scopes: append(models.StringList{}, scopes...), CreatedAt: now, UpdatedAt: now,
			}
			err := s.stores.Grants.Create(ctx, grant)
			if err == nil {
				return grant, nil
			}
			if errors.Is(err, models.ErrConflict) {
				continue
			}
			return nil, types.NewInternalError("failed to store grant").Wrap(err)
		}
		if oauthproto.ScopeSubset(scopes, grant.Scopes) {
			return grant, nil
		}
		for _, scope := range scopes {
			if !grant.Scopes.Contains(scope) {
				grant.Scopes = append(grant.Scopes, scope)
			}
		}
		if err := s.stores.Grants.Update(ctx, grant); err != nil {
			if errors.Is(err, models.ErrNotFound) {
				continue
			}
			return nil, types.NewInternalError("failed to store grant").Wrap(err)
		}
		return grant, nil
	}
	return nil, types.NewInternalError("failed to store grant")
}

// DenyConsent records the refusal and returns the access_denied redirect.
func (s *idpService) DenyConsent(ctx context.Context, userID, requestID string, metadata *types.RequestMetadata) (string, *types.GoAuthError) {
	record, pending, authErr := s.loadPending(ctx, requestID)
	if authErr != nil {
		return "", authErr
	}
	if err := s.stores.Tokens.MarkAsUsed(ctx, record.ID); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return "", types.NewIDPRequestNotFoundError()
		}
		return "", types.NewInternalError("failed to consume sign-in request").Wrap(err)
	}
	event := &types.IDPEventData{
		UserID: userID, ActorID: userID, ClientID: pending.ClientID, Scopes: pending.Scopes,
		Details: "Refused to sign in to client application " + pending.ClientID,
	}
	if metadata != nil {
		event.IP, event.UserAgent = metadata.IPAddress, metadata.UserAgent
	}
	s.emit(ctx, types.EventIDPConsentDenied, event)
	target, goErr := s.authorizationError(pending.RedirectURI, pending.State, CodeAccessDenied, "The user denied the request")
	if goErr != nil {
		return "", types.NewInternalError("failed to build redirect").Wrap(goErr)
	}
	return target, nil
}

// expired reports whether t is at or before now.
func expired(t time.Time, now time.Time) bool {
	return !now.Before(t)
}
