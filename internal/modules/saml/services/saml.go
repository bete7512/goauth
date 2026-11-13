package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bete7512/goauth/internal/authentication"
	"github.com/bete7512/goauth/internal/modules/saml/providers"
	"github.com/bete7512/goauth/internal/operation"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

const defaultRequestTTL = 10 * time.Minute

// samlContinuation is stored with the pending AuthnRequest so the ACS can
// finish the flow the browser started.
type samlContinuation struct {
	Connection string `json:"connection"`
	Redirect   string `json:"redirect"`
}

// InitiateLogin builds the AuthnRequest, records its ID and returns the IdP URL.
func (s *samlService) InitiateLogin(ctx context.Context, providerName, clientRedirectURI string) (*LoginStart, *types.GoAuthError) {
	provider, ok := s.registry.Get(providerName)
	if !ok {
		return nil, types.NewSAMLProviderNotFoundError(providerName)
	}

	// The request ID doubles as RelayState so the IdP echoes it back; the
	// ACS looks the pending request up by it and checks InResponseTo against it.
	redirectURL, requestID, err := provider.AuthnRequest(ctx)
	if err != nil || requestID == "" {
		s.logger.Errorf("saml: failed to build AuthnRequest for %s: %v", providerName, err)
		return nil, types.NewInternalError("failed to build SAML authentication request").Wrap(err)
	}

	ttl := s.config.RequestTTL
	if ttl <= 0 {
		ttl = defaultRequestTTL
	}
	data, err := json.Marshal(samlContinuation{Connection: providerName, Redirect: clientRedirectURI})
	if err != nil {
		return nil, types.NewInternalError("failed to encode continuation").Wrap(err)
	}
	now := time.Now()
	record := &models.Token{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    "",
		Type:      models.TokenTypeSAMLRequest,
		Token:     requestID,
		Data:      string(data),
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if err := s.tokenRepo.Create(ctx, record); err != nil {
		s.logger.Errorf("saml: failed to store AuthnRequest: %v", err)
		return nil, types.NewInternalError("failed to store SAML authentication request").Wrap(err)
	}

	s.logger.Trace("saml: initiated login", "provider", providerName, "request_id", requestID)
	return &LoginStart{RedirectURL: redirectURL, RequestID: requestID}, nil
}

// HandleACS consumes the pending request, verifies the response and signs the user in.
func (s *samlService) HandleACS(ctx context.Context, providerName, relayState string, r *http.Request, metadata *types.RequestMetadata) (*SAMLResult, *types.GoAuthError) {
	provider, ok := s.registry.Get(providerName)
	if !ok {
		return nil, types.NewSAMLProviderNotFoundError(providerName)
	}

	var possibleRequestIDs []string
	var clientRedirectURI string
	if relayState != "" {
		continuation, authErr := s.consumeRequest(ctx, providerName, relayState)
		if authErr != nil {
			return nil, authErr
		}
		possibleRequestIDs = []string{relayState}
		clientRedirectURI = continuation.Redirect
	} else if !provider.AllowIDPInitiated() {
		return nil, types.NewSAMLIDPInitiatedDisabledError()
	}

	identity, err := provider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		// The cause names certificates, time skew or audience details that
		// help the operator and nobody else.
		s.logger.Warnf("saml: response from %s rejected: %v", providerName, err)
		return nil, types.NewSAMLInvalidResponseError()
	}
	if identity == nil || identity.NameID == "" {
		s.logger.Warnf("saml: response from %s has no NameID", providerName)
		return nil, types.NewSAMLInvalidResponseError()
	}
	if identity.Issuer != "" && provider.IssuerEntityID() != "" && identity.Issuer != provider.IssuerEntityID() {
		s.logger.Warnf("saml: response from %s issued by %q, expected %q", providerName, identity.Issuer, provider.IssuerEntityID())
		return nil, types.NewSAMLInvalidResponseError()
	}

	user, isNewUser, authErr := s.findOrCreateUser(ctx, providerName, provider.IssuerEntityID(), identity)
	if authErr != nil {
		return nil, authErr
	}

	now := time.Now()
	user.LastLoginAt = &now
	var activityErr error
	if mutator, ok := s.userRepo.(models.UserCredentialMutator); ok {
		activityErr = mutator.RecordLogin(ctx, user.ID, user.TokenVersion, now)
	} else {
		activityErr = s.userRepo.Update(ctx, user)
	}
	if activityErr != nil {
		s.logger.Warnf("saml: failed to record login: %v", activityErr)
	}

	completion := authentication.ForModule(s.deps, s.tokenRepo, s.sessionRepo, "")
	result, authErr := completion.Complete(ctx, types.AuthenticationEvidence{
		User:     user,
		Method:   "saml",
		Metadata: metadata,
		Claims:   map[string]interface{}{"saml_provider": providerName},
	})
	if authErr != nil {
		return nil, authErr
	}
	if result.Status == types.ChallengeRequired {
		return &SAMLResult{User: user, IsNewUser: isNewUser, Provider: providerName, NameID: identity.NameID, ClientRedirectURI: clientRedirectURI, Challenges: result.Challenges}, nil
	}

	if s.deps.Events != nil {
		if emitErr := s.deps.Events.EmitAsync(ctx, types.EventAfterSAMLLogin, &types.SAMLLoginEventData{
			User:       user,
			Provider:   providerName,
			NameID:     identity.NameID,
			Issuer:     identity.Issuer,
			IsNewUser:  isNewUser,
			Attributes: identity.Attributes,
			Metadata:   metadata,
		}); emitErr != nil {
			s.logger.Warnf("saml: failed to emit after login event: %v", emitErr)
		}
	}

	s.logger.Infof("saml: user %s authenticated via %s (new: %v, session: %v)", user.ID, providerName, isNewUser, s.useSessionAuth())
	return &SAMLResult{
		User:              user,
		AccessToken:       result.AccessToken,
		RefreshToken:      result.RefreshToken,
		ExpiresIn:         result.ExpiresIn,
		IsNewUser:         isNewUser,
		Provider:          providerName,
		NameID:            identity.NameID,
		ClientRedirectURI: clientRedirectURI,
		SessionID:         result.SessionID,
	}, nil
}

// consumeRequest looks the pending AuthnRequest up by ID and marks it used.
// Exactly one response per request is accepted.
func (s *samlService) consumeRequest(ctx context.Context, providerName, requestID string) (*samlContinuation, *types.GoAuthError) {
	record, err := s.tokenRepo.FindByToken(ctx, requestID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewSAMLInvalidRequestError()
		}
		return nil, types.NewInternalError("failed to find SAML authentication request").Wrap(err)
	}
	if record.Type != models.TokenTypeSAMLRequest || record.Used {
		return nil, types.NewSAMLInvalidRequestError()
	}
	if record.ExpiresAt.Before(time.Now()) {
		return nil, types.NewSAMLRequestExpiredError()
	}
	var continuation samlContinuation
	if err := json.Unmarshal([]byte(record.Data), &continuation); err != nil || continuation.Connection != providerName {
		return nil, types.NewSAMLInvalidRequestError()
	}
	if err := s.tokenRepo.MarkAsUsed(ctx, record.ID); err != nil {
		return nil, types.NewSAMLInvalidRequestError()
	}
	return &continuation, nil
}

// findOrCreateUser resolves the asserted subject to a user: by linked
// account, then by email when linking is allowed, then by signup.
func (s *samlService) findOrCreateUser(ctx context.Context, providerName, issuer string, identity *providers.Identity) (*models.User, bool, *types.GoAuthError) {
	if !s.inTransaction && s.deps.Storage != nil {
		type identityResult struct {
			user    *models.User
			created bool
		}
		result, authErr := operation.Run(ctx, s.deps, func(deps config.ModuleDependencies) (identityResult, *types.GoAuthError) {
			copy := *s
			copy.deps = deps
			copy.inTransaction = true
			copy.userRepo = deps.Storage.Core().Users()
			copy.accountRepo = deps.Storage.OAuth().Accounts()
			user, created, err := copy.findOrCreateUser(ctx, providerName, issuer, identity)
			return identityResult{user: user, created: created}, err
		})
		return result.user, result.created, authErr
	}

	// 1. Subject already linked to a user.
	if identity.IsPersistent() {
		account, err := s.accountRepo.FindByProviderAndAccountID(ctx, providerName, identity.NameID)
		if err == nil && account != nil {
			if account.Type != string(models.AccountTypeSAML) || (account.Issuer != "" && account.Issuer != issuer) || (account.RealmID != "" && account.RealmID != "default") {
				return nil, false, types.NewSAMLAccountLinkingDisabledError()
			}
			user, err := s.userRepo.FindByID(ctx, account.UserID)
			if err != nil || user == nil {
				return nil, false, types.NewInternalError("linked identity is unavailable")
			}
			return user, false, nil
		} else if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, false, types.NewInternalError("failed to look up linked identity").Wrap(err)
		}
	}

	// 2. Existing user with the same email.
	if identity.Email != "" {
		existing, err := s.userRepo.FindByEmail(ctx, identity.Email)
		if err == nil && existing != nil {
			if !s.config.AllowAccountLinking || !s.config.TrustEmail {
				return nil, false, types.NewSAMLAccountLinkingDisabledError()
			}
			if identity.IsPersistent() {
				if linkErr := s.linkSubject(ctx, existing.ID, providerName, issuer, identity); linkErr != nil {
					return nil, false, types.NewInternalError("failed to link SAML subject").Wrap(linkErr)
				}
			}
			return existing, false, nil
		} else if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, false, types.NewInternalError("failed to look up user").Wrap(err)
		}
	}

	// 3. New user.
	if !s.config.AllowSignup {
		return nil, false, types.NewSAMLSignupDisabledError()
	}
	if identity.Email == "" {
		return nil, false, types.NewSAMLEmailRequiredError()
	}
	if !identity.IsPersistent() {
		return nil, false, types.NewSAMLSubjectNotPersistentError()
	}

	now := time.Now()
	user := &models.User{
		ID:            uuid.Must(uuid.NewV7()).String(),
		Email:         identity.Email,
		Name:          identity.Name,
		FirstName:     identity.FirstName,
		LastName:      identity.LastName,
		Username:      s.generateUsername(identity),
		PasswordHash:  "",
		Active:        true,
		EmailVerified: s.config.TrustEmail,
		CreatedAt:     now,
		UpdatedAt:     &now,
	}
	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.Errorf("saml: failed to create user: %v", err)
		return nil, false, types.NewInternalError("failed to create user").Wrap(err)
	}
	if linkErr := s.linkSubject(ctx, user.ID, providerName, issuer, identity); linkErr != nil {
		return nil, false, types.NewInternalError("failed to link SAML subject").Wrap(linkErr)
	}
	if s.deps.Events != nil {
		_ = s.deps.Events.EmitAsync(ctx, types.EventAfterSignup, &types.UserEventData{User: user})
	}
	return user, true, nil
}

func (s *samlService) linkSubject(ctx context.Context, userID, providerName, issuer string, identity *providers.Identity) error {
	now := time.Now()
	account := &models.Account{
		ID:                uuid.Must(uuid.NewV7()).String(),
		RealmID:           "default",
		Issuer:            issuer,
		UserID:            userID,
		Provider:          providerName,
		ProviderAccountID: identity.NameID,
		Type:              string(models.AccountTypeSAML),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.accountRepo.Create(ctx, account); err != nil {
		return err
	}
	if s.deps.Events != nil {
		_ = s.deps.Events.EmitAsync(ctx, types.EventSAMLLinkAdded, &types.OAuthLinkEventData{
			UserID:         userID,
			Provider:       providerName,
			ProviderUserID: identity.NameID,
		})
	}
	return nil
}

// Metadata returns the SP metadata document for a connection.
func (s *samlService) Metadata(providerName string) ([]byte, *types.GoAuthError) {
	provider, ok := s.registry.Get(providerName)
	if !ok {
		return nil, types.NewSAMLProviderNotFoundError(providerName)
	}
	out, err := provider.Metadata()
	if err != nil {
		s.logger.Errorf("saml: failed to render metadata for %s: %v", providerName, err)
		return nil, types.NewInternalError("failed to render SP metadata").Wrap(err)
	}
	return out, nil
}

// ListProviders returns the configured connection names.
func (s *samlService) ListProviders() []string {
	return s.registry.List()
}

// generateUsername derives a unique username from the asserted username or email.
func (s *samlService) generateUsername(identity *providers.Identity) string {
	base := identity.Username
	if base == "" {
		base = strings.SplitN(identity.Email, "@", 2)[0]
	}
	base = strings.ToLower(base)
	base = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, base)
	if len(base) > 20 {
		base = base[:20]
	}
	if base == "" {
		base = "user"
	}
	return fmt.Sprintf("%s_%s", base, uuid.Must(uuid.NewV7()).String()[:6])
}
