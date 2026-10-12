package authentication

import (
	"context"
	"encoding/json"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"time"
)

// Engine owns eligibility, challenges and strategy-specific credential issuance.
// Authenticators verify evidence; transports deliver the returned result.
type Engine struct {
	consume      *models.Token
	Store        types.Storage
	Config       *config.Config
	Security     types.SecurityManager
	Interceptors types.AuthInterceptorRegistry
	Tokens       models.TokenRepository
	Sessions     models.SessionRepository
}

func (e *Engine) Complete(ctx context.Context, evidence types.AuthenticationEvidence) (types.AuthenticationResult, *types.GoAuthError) {
	result := types.AuthenticationResult{Status: types.Denied}
	if err := security.CheckEligibility(evidence.User, e.Config.Core); err != nil {
		return result, err
	}
	phase := evidence.Phase
	if phase == "" {
		phase = types.PhaseLogin
	}
	claims := map[string]interface{}{}
	if e.Interceptors != nil {
		var err error
		claims, result.Challenges, result.Data, err = e.Interceptors.Run(ctx, &types.InterceptParams{Phase: phase, User: evidence.User, Metadata: evidence.Metadata, ExistingClaims: evidence.Claims, VerifiedMethods: evidence.Methods})
		if err != nil {
			return result, types.NewInternalError("authentication policy unavailable").Wrap(err)
		}
	}
	if len(result.Challenges) > 0 {
		return e.begin(ctx, evidence, result)
	}
	for key, value := range evidence.Claims {
		if security.IsReservedClaim(key) {
			return result, types.NewInternalError("reserved authentication claim")
		}
		claims[key] = value
	}
	authTime := evidence.AuthenticatedAt
	if authTime.IsZero() {
		authTime = time.Now().UTC()
	}
	methods := evidence.Methods
	if len(methods) == 0 {
		methods = []string{evidence.Method}
	}
	grant := types.GrantContext{AuthenticatedAt: authTime, Methods: methods, TokenVersion: evidence.User.TokenVersion}
	grant.OrganizationID, _ = claims["active_org_id"].(string)
	claims["amr"] = methods
	claims["auth_time"] = authTime.Unix()
	encoded, err := json.Marshal(grant)
	if err != nil {
		return result, types.NewInternalError("invalid grant context")
	}
	result.UserID = evidence.User.ID
	issue := func(tokens models.TokenRepository, sessions models.SessionRepository) error {
		if e.Config.Security.AuthStrategy == types.StrategySession {
			if sessions == nil {
				return types.NewInternalError("session storage unavailable")
			}
			result.SessionID = uuid.Must(uuid.NewV7()).String()
			claims["session_id"] = result.SessionID
			result.AccessToken, result.RefreshToken, err = e.Security.GenerateTokens(evidence.User, claims)
			if err == nil {
				now := time.Now()
				session := &models.Session{AuthData: string(encoded), ID: result.SessionID, UserID: evidence.User.ID, RefreshToken: e.Security.HashRefreshToken(result.RefreshToken), RefreshTokenExpiresAt: now.Add(e.Config.Security.Session.RefreshTokenTTL), ExpiresAt: now.Add(e.Config.Security.Session.SessionTTL), CreatedAt: now, UpdatedAt: now}
				if evidence.Metadata != nil {
					session.UserAgent = evidence.Metadata.UserAgent
					session.IPAddress = evidence.Metadata.IPAddress
				}
				if session.RefreshTokenExpiresAt.After(session.ExpiresAt) {
					session.RefreshTokenExpiresAt = session.ExpiresAt
				}
				err = sessions.Create(ctx, session)
			}
		} else {
			if tokens == nil {
				return types.NewInternalError("refresh token storage unavailable")
			}
			result.AccessToken, err = e.Security.GenerateAccessToken(*evidence.User, claims)
			if err == nil {
				var nonce string
				result.RefreshToken, nonce, err = e.Security.GenerateStatelessRefreshToken(evidence.User)
				if err == nil {
					now := time.Now()
					err = tokens.Create(ctx, &models.Token{Data: string(encoded), ID: uuid.Must(uuid.NewV7()).String(), UserID: evidence.User.ID, Type: "refresh_nonce", Token: nonce, CreatedAt: now, ExpiresAt: now.Add(e.Config.Security.Session.RefreshTokenTTL)})
				}
			}
		}
		return err
	}
	if e.Config.DurableEvents || e.consume != nil {
		atomic, ok := e.Store.(types.TransactionalStorage)
		if !ok {
			return result, types.NewInternalError("durable authentication requires transactional storage")
		}
		err = atomic.WithTransaction(ctx, func(tx types.Storage) error {
			outbox, ok := tx.(types.OutboxStore)
			if e.Config.DurableEvents && !ok {
				return types.NewInternalError("transaction requires outbox storage")
			}
			var sessions models.SessionRepository
			if tx.Session() != nil {
				sessions = tx.Session().Sessions()
			}
			if e.consume != nil {
				if err := tx.Core().Tokens().MarkAsUsed(ctx, e.consume.ID); err != nil {
					return err
				}
			}
			if err := issue(tx.Core().Tokens(), sessions); err != nil {
				return err
			}
			if !e.Config.DurableEvents {
				return nil
			}
			payload, _ := json.Marshal(map[string]interface{}{"user_id": evidence.User.ID, "session_id": result.SessionID, "methods": methods})
			return outbox.AppendEvent(ctx, types.EventEnvelope{Version: 1, ID: uuid.NewString(), Type: "authentication.completed", RealmID: "default", CreatedAt: time.Now().UTC(), Payload: payload})
		})
	} else {
		err = issue(e.Tokens, e.Sessions)
	}

	if err != nil {
		return types.AuthenticationResult{Status: types.Denied}, types.NewInternalError("failed to complete authentication").Wrap(err)
	}
	result.Status = types.Authenticated
	result.ExpiresIn = int64(e.Config.Security.Session.AccessTokenTTL.Seconds())
	return result, nil
}

// ForModule supports independently constructed module services as well as the
// shared runtime service installed by Auth.Initialize.
func ForModule(deps config.ModuleDependencies, tokens models.TokenRepository, sessions models.SessionRepository, strategy types.AuthStrategy) types.AuthenticationCompleter {
	if deps.Completion != nil {
		return deps.Completion
	}
	cfg := deps.Config.Clone()
	if strategy != "" {
		cfg.Security.AuthStrategy = strategy
	}
	return &Engine{Config: cfg, Security: deps.SecurityManager, Interceptors: deps.AuthInterceptors, Tokens: tokens, Sessions: sessions}
}
