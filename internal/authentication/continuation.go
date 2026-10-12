package authentication

import (
	"context"
	"encoding/json"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
	"slices"
	"time"
)

func (e *Engine) pendingRecord(state types.AuthenticationTransaction) (string, *models.Token, *types.GoAuthError) {
	signer, ok := e.Security.(interface {
		GenerateChallengeToken(string, string, time.Duration) (string, error)
	})
	if !ok {
		return "", nil, types.NewInternalError("challenge signer unavailable")
	}
	secret, err := signer.GenerateChallengeToken(state.UserID, uuid.NewString(), time.Until(state.ExpiresAt))
	if err != nil {
		return "", nil, types.NewInternalError("challenge generation failed").Wrap(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return "", nil, types.NewInternalError("invalid authentication transaction").Wrap(err)
	}
	return secret, &models.Token{ID: uuid.NewString(), UserID: state.UserID, Type: "2fa_pending", Token: e.Security.HashRefreshToken(secret), Data: string(data), CreatedAt: time.Now().UTC(), ExpiresAt: state.ExpiresAt}, nil
}

func (e *Engine) begin(ctx context.Context, evidence types.AuthenticationEvidence, result types.AuthenticationResult) (types.AuthenticationResult, *types.GoAuthError) {
	if e.consume != nil {
		return types.AuthenticationResult{Status: types.Denied}, types.NewUnauthorizedError()
	}
	if e.Tokens == nil {
		return result, types.NewInternalError("authentication transaction storage unavailable")
	}
	methods := evidence.Methods
	if len(methods) == 0 {
		methods = []string{evidence.Method}
	}
	authTime := evidence.AuthenticatedAt
	if authTime.IsZero() {
		authTime = time.Now().UTC()
	}
	state := types.AuthenticationTransaction{Version: 1, RealmID: "default", UserID: evidence.User.ID, TokenVersion: evidence.User.TokenVersion, AuthenticatedAt: authTime, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), Methods: methods, Claims: evidence.Claims}
	for _, challenge := range result.Challenges {
		if !slices.Contains(state.Required, challenge.Type) {
			state.Required = append(state.Required, challenge.Type)
		}
	}
	secret, record, err := e.pendingRecord(state)
	if err != nil {
		return result, err
	}
	if err := e.Tokens.Create(ctx, record); err != nil {
		return result, types.NewInternalError("persist authentication transaction").Wrap(err)
	}
	for i := range result.Challenges {
		if result.Challenges[i].Data == nil {
			result.Challenges[i].Data = map[string]interface{}{}
		}
		result.Challenges[i].Data["temp_token"] = secret
	}
	result.Status = types.ChallengeRequired
	return result, nil
}

func (e *Engine) Resume(ctx context.Context, secret string, factor types.LoginChallengeType) (types.AuthenticationResult, *types.GoAuthError) {
	denied := types.AuthenticationResult{Status: types.Denied}
	claims, err := security.ValidateCredential(e.Security, secret, "2fa_pending")
	if err != nil || e.Store == nil || e.Tokens == nil {
		return denied, types.NewInvalidTokenError()
	}
	record, err := e.Tokens.FindByToken(ctx, e.Security.HashRefreshToken(secret))
	if err != nil || record == nil || record.Type != "2fa_pending" || record.Used || record.UserID != claims["sub"] || record.Attempts > 10 || !time.Now().Before(record.ExpiresAt) {
		return denied, types.NewInvalidTokenError()
	}
	var state types.AuthenticationTransaction
	if json.Unmarshal([]byte(record.Data), &state) != nil || state.Version != 1 || state.RealmID != "default" || state.UserID != record.UserID || !time.Now().Before(state.ExpiresAt) || !slices.Contains(state.Required, factor) {
		return denied, types.NewInvalidTokenError()
	}
	user, err := e.Store.Core().Users().FindByID(ctx, state.UserID)
	if err != nil || user == nil || state.TokenVersion != user.TokenVersion {
		return denied, types.NewInvalidTokenError()
	}
	if authErr := security.CheckEligibility(user, e.Config.Core); authErr != nil {
		return denied, authErr
	}
	state.Required = slices.DeleteFunc(state.Required, func(required types.LoginChallengeType) bool { return required == factor })
	state.Methods = append(state.Methods, string(factor))
	if len(state.Required) > 0 {
		next, replacement, authErr := e.pendingRecord(state)
		if authErr != nil {
			return denied, authErr
		}
		rotator, ok := e.Tokens.(models.TokenRotator)
		if !ok {
			return denied, types.NewInternalError("atomic continuation transition unavailable")
		}
		if err := rotator.Rotate(ctx, record, replacement); err != nil {
			return denied, types.NewInvalidTokenError()
		}
		result := types.AuthenticationResult{Status: types.ChallengeRequired}
		for _, required := range state.Required {
			result.Challenges = append(result.Challenges, types.LoginChallenge{Type: required, Data: map[string]interface{}{"temp_token": next}})
		}
		return result, nil
	}
	completed := *e
	completed.consume = record
	return completed.Complete(ctx, types.AuthenticationEvidence{User: user, Phase: types.PhaseResume, Method: string(factor), Methods: state.Methods, AuthenticatedAt: state.AuthenticatedAt, Claims: state.Claims})
}
