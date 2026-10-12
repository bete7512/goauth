package security

import (
	"context"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/types"
	"time"
)

// ValidateAccess is the common online credential boundary for every transport.
func ValidateAccess(ctx context.Context, cfg *config.Config, manager types.SecurityManager, token string) (types.Principal, error) {
	denied := types.Principal{}
	claims, err := ValidateCredential(manager, token, "access")
	if err != nil {
		return denied, types.NewUnauthorizedError()
	}
	store := cfg.Storage
	if store == nil || store.Core() == nil {
		return denied, types.NewInternalError("authentication unavailable")
	}
	core := store.Core()
	if cfg.Core != nil && cfg.Core.CustomStorage != nil {
		core = cfg.Core.CustomStorage
	}
	userID := claims["sub"].(string)
	user, err := core.Users().FindByID(ctx, userID)
	version, ok := claims["token_version"].(float64)
	if err != nil || user == nil || !ok || version != float64(user.TokenVersion) || CheckEligibility(user, cfg.Core) != nil {
		return denied, types.NewUnauthorizedError()
	}
	principal := types.Principal{UserID: userID, RealmID: "default", TokenVersion: user.TokenVersion}
	if expiry, ok := claims["exp"].(float64); ok {
		principal.ExpiresAt = time.Unix(int64(expiry), 0)
	}
	if authTime, ok := claims["auth_time"].(float64); ok {
		principal.AuthenticatedAt = time.Unix(int64(authTime), 0)
	}
	if methods, ok := claims["amr"].([]interface{}); ok {
		for _, raw := range methods {
			if method, ok := raw.(string); ok {
				principal.Methods = append(principal.Methods, method)
			}
		}
	}
	if sessionID, ok := claims["session_id"].(string); ok && sessionID != "" {
		if store.Session() == nil {
			return denied, types.NewUnauthorizedError()
		}
		session, err := store.Session().Sessions().FindByID(ctx, sessionID)
		if err != nil || session == nil || session.UserID != userID || !time.Now().Before(session.ExpiresAt) {
			return denied, types.NewUnauthorizedError()
		}
		principal.SessionID = sessionID
		if principal.AuthenticatedAt.IsZero() {
			principal.AuthenticatedAt = session.CreatedAt
		}
	} else if cfg.Security.AuthStrategy == types.StrategySession {
		return denied, types.NewUnauthorizedError()
	}
	principal.OrganizationID, _ = claims["active_org_id"].(string)
	if principal.OrganizationID != "" {
		if store.Organization() == nil {
			return denied, types.NewUnauthorizedError()
		}
		member, err := store.Organization().Members().FindByOrgAndUser(ctx, principal.OrganizationID, userID)
		if err != nil || member == nil || !types.HasMinimumRole(member.Role, types.OrgRoleMember) {
			return denied, types.NewUnauthorizedError()
		}
		org, err := store.Organization().Organizations().FindByID(ctx, principal.OrganizationID)
		if err != nil || org == nil || !org.Active {
			return denied, types.NewUnauthorizedError()
		}
	}
	return principal, nil
}
