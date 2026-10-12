package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bete7512/goauth/internal/authentication"
	"net/http"
	"strings"
	"time"

	coredto "github.com/bete7512/goauth/internal/modules/core/handlers/dto"
	"github.com/bete7512/goauth/internal/modules/passkeys/handlers/dto"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// PasskeyService drives the WebAuthn registration and login ceremonies,
// manages stored credentials, and returns auth tokens on successful login.
type PasskeyService interface {
	BeginRegistration(ctx context.Context, userID string) (*dto.BeginRegistrationResponse, *types.GoAuthError)
	FinishRegistration(ctx context.Context, userID string, req *dto.FinishRegistrationRequest) (*dto.PasskeySummary, *types.GoAuthError)
	BeginLogin(ctx context.Context) (*dto.BeginLoginResponse, *types.GoAuthError)
	FinishLogin(ctx context.Context, req *dto.FinishLoginRequest) (*coredto.AuthResponse, *types.GoAuthError)
	ListCredentials(ctx context.Context, userID string) ([]*dto.PasskeySummary, *types.GoAuthError)
	DeleteCredential(ctx context.Context, userID, credentialID string) *types.GoAuthError
	RenameCredential(ctx context.Context, userID, credentialID, name string) *types.GoAuthError
}

type passkeyService struct {
	deps            config.ModuleDependencies
	config          *config.PasskeysModuleConfig
	webauthn        *webauthn.WebAuthn
	passkeyRepo     models.PasskeyRepository
	userRepo        models.UserRepository
	securityManager types.SecurityManager
}

func NewPasskeyService(
	deps config.ModuleDependencies,
	cfg *config.PasskeysModuleConfig,
	wa *webauthn.WebAuthn,
	passkeyRepo models.PasskeyRepository,
	userRepo models.UserRepository,
	securityManager types.SecurityManager,
) *passkeyService {
	return &passkeyService{
		deps:            deps,
		config:          cfg,
		webauthn:        wa,
		passkeyRepo:     passkeyRepo,
		userRepo:        userRepo,
		securityManager: securityManager,
	}
}

// --- Registration ---

func (s *passkeyService) BeginRegistration(ctx context.Context, userID string) (*dto.BeginRegistrationResponse, *types.GoAuthError) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, types.NewUserNotFoundError()
		}
		return nil, types.NewInternalError("failed to find user").Wrap(err)
	}

	existing, err := s.passkeyRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, types.NewInternalError("failed to list passkeys").Wrap(err)
	}
	wu := newWebAuthnUser(user, existing)

	creation, session, waErr := s.webauthn.BeginRegistration(wu)
	if waErr != nil {
		return nil, types.NewInternalError("webauthn begin registration").Wrap(waErr)
	}

	token, authErr := s.sealSession(ctx, session, "passkey_registration")
	if authErr != nil {
		return nil, authErr
	}

	return &dto.BeginRegistrationResponse{
		ChallengeToken: token,
		PublicKey:      creation.Response,
	}, nil
}

func (s *passkeyService) FinishRegistration(ctx context.Context, userID string, req *dto.FinishRegistrationRequest) (*dto.PasskeySummary, *types.GoAuthError) {
	session, authErr := s.openSession(ctx, req.ChallengeToken, "passkey_registration")
	if authErr != nil {
		return nil, authErr
	}

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, types.NewUserNotFoundError()
	}
	existing, err := s.passkeyRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, types.NewInternalError("failed to list passkeys").Wrap(err)
	}
	wu := newWebAuthnUser(user, existing)

	httpReq, buildErr := s.buildFinishRequest(req.CredentialResponse)
	if buildErr != nil {
		return nil, buildErr
	}

	credential, waErr := s.webauthn.FinishRegistration(wu, *session, httpReq)
	if waErr != nil {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, waErr.Error(), http.StatusBadRequest)
	}

	stored := credentialToModel(userID, credential, req.Name)
	if err := s.passkeyRepo.Create(ctx, stored); err != nil {
		return nil, types.NewInternalError("failed to store passkey").Wrap(err)
	}

	return credentialToSummary(stored), nil
}

// --- Login (discoverable credentials / usernameless) ---

func (s *passkeyService) BeginLogin(ctx context.Context) (*dto.BeginLoginResponse, *types.GoAuthError) {
	assertion, session, waErr := s.webauthn.BeginDiscoverableLogin()
	if waErr != nil {
		return nil, types.NewInternalError("webauthn begin login").Wrap(waErr)
	}

	token, authErr := s.sealSession(ctx, session, "passkey_login")
	if authErr != nil {
		return nil, authErr
	}

	return &dto.BeginLoginResponse{
		ChallengeToken: token,
		PublicKey:      assertion.Response,
	}, nil
}

func (s *passkeyService) FinishLogin(ctx context.Context, req *dto.FinishLoginRequest) (*coredto.AuthResponse, *types.GoAuthError) {
	session, authErr := s.openSession(ctx, req.ChallengeToken, "passkey_login")
	if authErr != nil {
		return nil, authErr
	}

	httpReq, buildErr := s.buildFinishRequest(req.CredentialResponse)
	if buildErr != nil {
		return nil, buildErr
	}

	var resolvedUser *models.User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		stored, err := s.passkeyRepo.FindByCredentialID(ctx, rawID)
		if err != nil {
			return nil, fmt.Errorf("passkey not found: %w", err)
		}
		if len(userHandle) > 0 && string(userHandle) != stored.UserID {
			return nil, errors.New("userHandle mismatch")
		}
		u, err := s.userRepo.FindByID(ctx, stored.UserID)
		if err != nil {
			return nil, err
		}
		credentials, err := s.passkeyRepo.ListByUserID(ctx, stored.UserID)
		if err != nil {
			return nil, err
		}
		resolvedUser = u
		return newWebAuthnUser(u, credentials), nil
	}

	credential, waErr := s.webauthn.FinishDiscoverableLogin(handler, *session, httpReq)
	if waErr != nil {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, waErr.Error(), http.StatusUnauthorized)
	}
	if resolvedUser == nil {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "unable to resolve user from passkey", http.StatusUnauthorized)
	}

	stored, err := s.passkeyRepo.FindByCredentialID(ctx, credential.ID)
	if err != nil {
		return nil, types.NewInternalError("failed to load passkey").Wrap(err)
	}
	now := time.Now()
	if err := s.passkeyRepo.UpdateSignCount(ctx, stored.ID, credential.Authenticator.SignCount); err != nil {
		return nil, types.NewInvalidTokenError().Wrap(err)
	}

	var tokens models.TokenRepository
	if s.deps.Storage != nil && s.deps.Storage.Core() != nil {
		tokens = s.deps.Storage.Core().Tokens()
	}
	completion := authentication.ForModule(s.deps, tokens, nil, "")
	result, authErr := completion.Complete(ctx, types.AuthenticationEvidence{User: resolvedUser, Method: "passkey"})
	if authErr != nil {
		return nil, authErr
	}
	if result.Status == types.ChallengeRequired {
		return &coredto.AuthResponse{Challenges: result.Challenges, Message: "Authentication challenge required"}, nil
	}
	accessToken, refreshToken := result.AccessToken, result.RefreshToken

	resolvedUser.LastLoginAt = &now
	var updateErr error
	if mutator, ok := s.userRepo.(models.UserCredentialMutator); ok {
		updateErr = mutator.RecordLogin(ctx, resolvedUser.ID, resolvedUser.TokenVersion, now)
	} else {
		updateErr = s.userRepo.Update(ctx, resolvedUser)
	}
	if err := updateErr; err != nil {
		s.deps.Logger.Errorf("passkeys: failed to update last login: %v", err)
	}

	expiresIn := int64(s.deps.Config.Security.Session.AccessTokenTTL.Seconds())
	return &coredto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
		User:         userToDTO(resolvedUser),
		ExpiresIn:    expiresIn,
		Message:      "Passkey login successful",
	}, nil
}

// --- Credential management ---

func (s *passkeyService) ListCredentials(ctx context.Context, userID string) ([]*dto.PasskeySummary, *types.GoAuthError) {
	creds, err := s.passkeyRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, types.NewInternalError("failed to list passkeys").Wrap(err)
	}
	out := make([]*dto.PasskeySummary, 0, len(creds))
	for _, c := range creds {
		out = append(out, credentialToSummary(c))
	}
	return out, nil
}

func (s *passkeyService) DeleteCredential(ctx context.Context, userID, credentialID string) *types.GoAuthError {
	cred, err := s.passkeyRepo.FindByID(ctx, credentialID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewGoAuthError(types.ErrPasskeyNotFound, "passkey not found", http.StatusNotFound)
		}
		return types.NewInternalError("failed to find passkey").Wrap(err)
	}
	if cred.UserID != userID {
		return types.NewGoAuthError(types.ErrForbidden, "passkey does not belong to user", http.StatusForbidden)
	}
	if err := s.passkeyRepo.Delete(ctx, credentialID); err != nil {
		return types.NewInternalError("failed to delete passkey").Wrap(err)
	}
	return nil
}

func (s *passkeyService) RenameCredential(ctx context.Context, userID, credentialID, name string) *types.GoAuthError {
	cred, err := s.passkeyRepo.FindByID(ctx, credentialID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewGoAuthError(types.ErrPasskeyNotFound, "passkey not found", http.StatusNotFound)
		}
		return types.NewInternalError("failed to find passkey").Wrap(err)
	}
	if cred.UserID != userID {
		return types.NewGoAuthError(types.ErrForbidden, "passkey does not belong to user", http.StatusForbidden)
	}
	if err := s.passkeyRepo.UpdateName(ctx, credentialID, name); err != nil {
		return types.NewInternalError("failed to rename passkey").Wrap(err)
	}
	return nil
}

// --- Session sealing ---

// The WebAuthn SessionData must survive the round trip between begin and finish.
// We encrypt it with the SecurityManager so the client can hold the opaque blob
// while a stored, purpose-bound one-time record prevents ceremony replay.
func (s *passkeyService) sealSession(ctx context.Context, session *webauthn.SessionData, purpose string) (string, *types.GoAuthError) {
	if session.Expires.IsZero() || session.Expires.After(time.Now().Add(5*time.Minute)) {
		session.Expires = time.Now().Add(5 * time.Minute)
	}
	raw, err := json.Marshal(session)
	if err != nil {
		return "", types.NewInternalError("marshal session").Wrap(err)
	}
	sealed, err := s.securityManager.Encrypt(string(raw))
	if err != nil {
		return "", types.NewInternalError("seal session").Wrap(err)
	}
	if s.deps.Storage == nil || s.deps.Storage.Core() == nil {
		return "", types.NewInternalError("passkey continuation storage required")
	}
	err = s.deps.Storage.Core().Tokens().Create(ctx, &models.Token{ID: uuid.Must(uuid.NewV7()).String(), UserID: string(session.UserID), Type: purpose, Token: s.securityManager.HashRefreshToken(sealed), CreatedAt: time.Now(), ExpiresAt: session.Expires})
	if err != nil {
		return "", types.NewInternalError("store passkey continuation").Wrap(err)
	}
	return sealed, nil
}

func (s *passkeyService) openSession(ctx context.Context, token, purpose string) (*webauthn.SessionData, *types.GoAuthError) {
	if token == "" {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "missing challenge token", http.StatusBadRequest)
	}
	raw, err := s.securityManager.Decrypt(token)
	if err != nil {
		return nil, types.NewGoAuthError(types.ErrInvalidToken, "invalid challenge token", http.StatusBadRequest)
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(raw), &session); err != nil {
		return nil, types.NewInternalError("unmarshal session").Wrap(err)
	}
	if !session.Expires.IsZero() && time.Now().After(session.Expires) {
		return nil, types.NewGoAuthError(types.ErrTokenExpired, "challenge expired", http.StatusBadRequest)
	}
	if s.deps.Storage == nil || s.deps.Storage.Core() == nil {
		return nil, types.NewInternalError("passkey continuation storage required")
	}
	repo := s.deps.Storage.Core().Tokens()
	record, err := repo.FindByToken(ctx, s.securityManager.HashRefreshToken(token))
	if err != nil || record == nil || record.Type != purpose || record.UserID != string(session.UserID) || record.Used || !time.Now().Before(record.ExpiresAt) {
		return nil, types.NewInvalidTokenError()
	}
	if err := repo.MarkAsUsed(ctx, record.ID); err != nil {
		return nil, types.NewInvalidTokenError()
	}
	return &session, nil
}

// buildFinishRequest constructs an http.Request the webauthn lib can parse from
// the JSON CredentialResponse submitted by the client. The lib only reads the
// request body, so a no-op URL and POST method are sufficient.
func (s *passkeyService) buildFinishRequest(credential json.RawMessage) (*http.Request, *types.GoAuthError) {
	if len(credential) == 0 {
		return nil, types.NewGoAuthError(types.ErrInvalidRequestBody, "missing credential response", http.StatusBadRequest)
	}
	req, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader(credential))
	if err != nil {
		return nil, types.NewInternalError("build finish request").Wrap(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// --- WebAuthn user adapter ---

type webAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func newWebAuthnUser(u *models.User, stored []*models.PasskeyCredential) *webAuthnUser {
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		creds = append(creds, storedToCredential(c))
	}
	name := u.Email
	display := firstNonEmpty(u.Name, u.Username, u.Email)
	return &webAuthnUser{
		id:          []byte(u.ID),
		name:        name,
		displayName: display,
		credentials: creds,
	}
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webAuthnUser) WebAuthnName() string                       { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// --- Conversions ---

func credentialToModel(userID string, c *webauthn.Credential, name string) *models.PasskeyCredential {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return &models.PasskeyCredential{
		ID:                uuid.Must(uuid.NewV7()).String(),
		UserID:            userID,
		CredentialID:      c.ID,
		PublicKey:         c.PublicKey,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		AAGUID:            c.Authenticator.AAGUID,
		SignCount:         c.Authenticator.SignCount,
		Transports:        strings.Join(transports, ","),
		BackupEligible:    c.Flags.BackupEligible,
		BackupState:       c.Flags.BackupState,
		UserPresent:       c.Flags.UserPresent,
		UserVerified:      c.Flags.UserVerified,
		Name:              name,
		CreatedAt:         time.Now(),
	}
}

func storedToCredential(c *models.PasskeyCredential) webauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	for _, t := range strings.Split(c.Transports, ",") {
		if t = strings.TrimSpace(t); t != "" {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
	}
	return webauthn.Credential{
		ID:                c.CredentialID,
		PublicKey:         c.PublicKey,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		Transport:         transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    c.UserPresent,
			UserVerified:   c.UserVerified,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

func credentialToSummary(c *models.PasskeyCredential) *dto.PasskeySummary {
	return &dto.PasskeySummary{
		ID:         c.ID,
		Name:       c.Name,
		Transports: splitTransports(c.Transports),
		CreatedAt:  c.CreatedAt,
		LastUsedAt: c.LastUsedAt,
	}
}

func splitTransports(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func userToDTO(u *models.User) *coredto.UserDTO {
	return &coredto.UserDTO{
		ID:                  u.ID,
		FirstName:           u.FirstName,
		LastName:            u.LastName,
		Name:                u.Name,
		Email:               u.Email,
		Username:            u.Username,
		Avatar:              u.Avatar,
		PhoneNumber:         u.PhoneNumber,
		Active:              u.Active,
		EmailVerified:       u.EmailVerified,
		PhoneNumberVerified: u.PhoneNumberVerified,
		CreatedAt:           u.CreatedAt,
		UpdatedAt:           u.UpdatedAt,
		LastLoginAt:         u.LastLoginAt,
	}
}
