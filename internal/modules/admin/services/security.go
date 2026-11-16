package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// ErrFeatureUnavailable marks an operation whose store the backend does not
// provide, for example sessions when the stateless strategy is used.
var errFeatureUnavailable = types.NewValidationError("this feature is not enabled")

// UserSecurity is everything a user can sign in with or is signed in by,
// for the administrators' view of an account. A nil list means the feature's
// store is not available.
type UserSecurity struct {
	LinkedAccounts []*models.Account
	Sessions       []*models.Session
	TwoFactor      *models.TwoFactor // nil when two-factor authentication was never set up
	BackupCodes    int               // unused backup codes left
	Passkeys       []*models.PasskeyCredential
	HasTwoFactor   bool // the two-factor store is available
	HasPasskeys    bool // the passkey store is available
}

// Security returns a user's linked accounts, sessions, two-factor state and
// passkeys.
func (s *adminService) Security(ctx context.Context, userID string) (*UserSecurity, *types.GoAuthError) {
	if _, authErr := s.authorize(ctx); authErr != nil {
		return nil, authErr
	}
	store := s.deps.Storage
	out := &UserSecurity{}
	if oauth := store.OAuth(); oauth != nil && (s.registered(types.OAuthModule) || s.registered(types.SAMLModule)) {
		accounts, err := oauth.Accounts().FindByUserID(ctx, userID)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, types.NewInternalError("failed to load linked accounts").Wrap(err)
		}
		out.LinkedAccounts = nonNil(accounts)
	}
	if sessions := store.Session(); sessions != nil && s.deps.Config.Security.AuthStrategy == types.StrategySession {
		opts := models.SessionListOpts{ListingOpts: models.ListingOpts{Limit: 100, SortField: "created_at", SortDir: "desc"}}
		opts.Normalize(100)
		list, _, err := sessions.Sessions().FindByUserID(ctx, userID, opts)
		if err != nil {
			return nil, types.NewInternalError("failed to load sessions").Wrap(err)
		}
		out.Sessions = nonNil(list)
	}
	if tf := store.TwoFactorAuth(); tf != nil && s.registered(types.TwoFactorModule) {
		out.HasTwoFactor = true
		config, err := tf.TwoFactor().GetByUserID(ctx, userID)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, types.NewInternalError("failed to load two-factor settings").Wrap(err)
		}
		if err == nil && config != nil {
			out.TwoFactor = config
		}
		codes, err := tf.BackupCodes().GetUnusedByUserID(ctx, userID)
		if err == nil {
			out.BackupCodes = len(codes)
		}
	}
	if passkeys := store.Passkeys(); passkeys != nil && s.registered(types.PasskeysModule) {
		out.HasPasskeys = true
		list, err := passkeys.Passkeys().ListByUserID(ctx, userID)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			return nil, types.NewInternalError("failed to load passkeys").Wrap(err)
		}
		out.Passkeys = nonNil(list)
	}
	return out, nil
}

// UnlinkAccount removes an external identity (OAuth or SAML) from a user.
// It does not check that the user keeps another way to sign in: an
// administrator may need to cut a compromised identity off.
func (s *adminService) UnlinkAccount(ctx context.Context, userID, accountID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	oauth := s.deps.Storage.OAuth()
	if oauth == nil || (!s.registered(types.OAuthModule) && !s.registered(types.SAMLModule)) {
		return errFeatureUnavailable
	}
	account, err := oauth.Accounts().FindByID(ctx, accountID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (account == nil || account.UserID != userID)) {
		return types.NewNotFoundError("linked account")
	}
	if err != nil {
		return types.NewInternalError("failed to load linked account").Wrap(err)
	}
	if err := oauth.Accounts().Delete(ctx, account.ID); err != nil {
		return types.NewInternalError("failed to unlink account").Wrap(err)
	}
	s.securityEvent(ctx, actor.ID, userID, fmt.Sprintf("Unlinked %s identity %s", account.Provider, account.ProviderAccountID))
	return nil
}

// RevokeSession ends one of a user's sessions.
func (s *adminService) RevokeSession(ctx context.Context, userID, sessionID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	sessions := s.deps.Storage.Session()
	if sessions == nil || s.deps.Config.Security.AuthStrategy != types.StrategySession {
		return errFeatureUnavailable
	}
	session, err := sessions.Sessions().FindByID(ctx, sessionID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (session == nil || session.UserID != userID)) {
		return types.NewSessionNotFoundError()
	}
	if err != nil {
		return types.NewInternalError("failed to load session").Wrap(err)
	}
	if err := sessions.Sessions().Delete(ctx, session.ID); err != nil {
		return types.NewInternalError("failed to revoke session").Wrap(err)
	}
	s.securityEvent(ctx, actor.ID, userID, "Revoked one session")
	return nil
}

// SignOutEverywhere invalidates every credential the user holds: access and
// refresh tokens through the token version, and every session.
func (s *adminService) SignOutEverywhere(ctx context.Context, userID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	mutator, ok := s.userRepository.(models.UserCredentialMutator)
	if !ok {
		return types.NewInternalError("the user store cannot revoke tokens")
	}
	if err := mutator.RevokeTokens(ctx, userID); err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return types.NewUserNotFoundError()
		}
		return types.NewInternalError("failed to revoke tokens").Wrap(err)
	}
	if sessions := s.deps.Storage.Session(); sessions != nil && s.deps.Config.Security.AuthStrategy == types.StrategySession {
		if err := sessions.Sessions().DeleteByUserID(ctx, userID); err != nil {
			return types.NewInternalError("failed to revoke sessions").Wrap(err)
		}
	}
	s.securityEvent(ctx, actor.ID, userID, "Signed out of every device")
	return nil
}

// ResetTwoFactor removes a user's two-factor settings and backup codes, for
// a user who lost their authenticator. The user can set it up again.
func (s *adminService) ResetTwoFactor(ctx context.Context, userID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	tf := s.deps.Storage.TwoFactorAuth()
	if tf == nil || !s.registered(types.TwoFactorModule) {
		return errFeatureUnavailable
	}
	err := tf.WithTransaction(ctx, func(tx types.TwoFactorStorage) error {
		if err := tx.BackupCodes().DeleteByUserID(ctx, userID); err != nil {
			return err
		}
		if err := tx.TwoFactor().Delete(ctx, userID); err != nil && !errors.Is(err, models.ErrNotFound) {
			return err
		}
		return nil
	})
	if err != nil {
		return types.NewInternalError("failed to reset two-factor authentication").Wrap(err)
	}
	s.securityEvent(ctx, actor.ID, userID, "Reset two-factor authentication")
	return nil
}

// DeletePasskey removes one of a user's passkeys.
func (s *adminService) DeletePasskey(ctx context.Context, userID, passkeyID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	passkeys := s.deps.Storage.Passkeys()
	if passkeys == nil || !s.registered(types.PasskeysModule) {
		return errFeatureUnavailable
	}
	passkey, err := passkeys.Passkeys().FindByID(ctx, passkeyID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && (passkey == nil || passkey.UserID != userID)) {
		return types.NewNotFoundError("passkey")
	}
	if err != nil {
		return types.NewInternalError("failed to load passkey").Wrap(err)
	}
	if err := passkeys.Passkeys().Delete(ctx, passkey.ID); err != nil {
		return types.NewInternalError("failed to delete passkey").Wrap(err)
	}
	s.securityEvent(ctx, actor.ID, userID, "Removed passkey "+passkey.Name)
	return nil
}

// securityEvent records an administrator's change to a user's sign-in
// methods. The audit module stores it as admin.user.updated.
func (s *adminService) securityEvent(ctx context.Context, actorID, userID, details string) {
	email := ""
	if user, err := s.userRepository.FindByID(ctx, userID); err == nil && user != nil {
		email = user.Email
	}
	_ = s.deps.Events.EmitAsync(ctx, types.EventAdminUserUpdated, map[string]interface{}{
		"actor_id":     actorID,
		"target_id":    userID,
		"target_type":  "user",
		"target_email": email,
		"details":      details,
	})
}

func nonNil[T any](list []T) []T {
	if list == nil {
		return []T{}
	}
	return list
}

// registered reports whether a module is registered. A store can exist
// without its tables, which are created only by the module's migrations.
func (s *adminService) registered(name types.ModuleName) bool {
	if s.deps.Lookup == nil {
		return true
	}
	_, ok := s.deps.Lookup(string(name))
	return ok
}
