package services

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/session/handlers/dto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// Refresh refreshes the access token using a refresh token
func (s *sessionService) Refresh(ctx context.Context, req *dto.RefreshRequest) (dto.AuthResponse, *types.GoAuthError) {
	// Hash the incoming refresh token and look up by hash
	tokenHash := s.securityManager.HashRefreshToken(req.RefreshToken)
	session, err := s.sessionRepository.FindByToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to find session by token").Wrap(err)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return dto.AuthResponse{}, types.NewSessionExpiredError()
	}

	// Check if refresh token is expired
	if session.RefreshTokenExpiresAt.Before(time.Now()) {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Get user
	user, err := s.userRepository.FindByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to find user").Wrap(err)
	}

	var grant types.GrantContext
	if session.AuthData != "" {
		if err := json.Unmarshal([]byte(session.AuthData), &grant); err != nil {
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
	}
	if grant.TokenVersion != user.TokenVersion {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}
	if grant.AuthenticatedAt.IsZero() {
		grant.AuthenticatedAt = session.CreatedAt
	}
	// Reevaluate current policy while retaining the original authentication time.
	if authErr := security.CheckEligibility(user, s.deps.Config.Core); authErr != nil {
		return dto.AuthResponse{}, authErr
	}
	interceptClaims, challenges, responseData, interceptErr := s.deps.AuthInterceptors.Run(ctx, &types.InterceptParams{
		VerifiedMethods: grant.Methods,
		ExistingClaims:  map[string]interface{}{"active_org_id": grant.OrganizationID},
		Phase:           types.PhaseRefresh,
		User:            user,
	})
	if interceptErr != nil {
		return dto.AuthResponse{}, types.NewInternalError("Token refresh interrupted")
	}
	if len(challenges) > 0 && s.deps.Completion != nil {
		result, authErr := s.deps.Completion.Complete(ctx, types.AuthenticationEvidence{User: user, Method: "refresh", Phase: types.PhaseRefresh, Methods: grant.Methods, AuthenticatedAt: grant.AuthenticatedAt, Claims: map[string]interface{}{"active_org_id": grant.OrganizationID}})
		if authErr != nil {
			return dto.AuthResponse{}, authErr
		}
		return dto.AuthResponse{Challenges: result.Challenges, Message: "Authentication challenge required"}, nil
	}
	if len(challenges) > 0 {
		return dto.AuthResponse{Challenges: challenges, Message: "Authentication challenge required"}, nil
	}

	// Generate new session ID for rotation
	newSessionID := session.ID

	// Merge interceptor claims with session_id
	tokenClaims := map[string]interface{}{"session_id": newSessionID, "amr": grant.Methods, "auth_time": grant.AuthenticatedAt.Unix()}
	for k, v := range interceptClaims {
		tokenClaims[k] = v
	}

	// Generate new tokens with enriched claims
	accessToken, newRefreshToken, err := s.securityManager.GenerateTokens(user, tokenClaims)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to generate tokens").Wrap(err)
	}

	// The logical session and absolute expiry survive refresh. A conditional
	// update allows only one caller to replace the expected refresh secret.
	rotator, ok := s.sessionRepository.(models.SessionRotator)
	if !ok {
		return dto.AuthResponse{}, types.NewInternalError("session storage requires atomic rotation")
	}
	session.RefreshToken = s.securityManager.HashRefreshToken(newRefreshToken)
	session.RefreshTokenExpiresAt = time.Now().Add(s.deps.Config.Security.Session.RefreshTokenTTL)
	if session.RefreshTokenExpiresAt.After(session.ExpiresAt) {
		session.RefreshTokenExpiresAt = session.ExpiresAt
	}
	session.UpdatedAt = time.Now()

	if err := rotator.RotateToken(ctx, tokenHash, session); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to rotate session").Wrap(err)
	}

	return dto.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(s.deps.Config.Security.Session.AccessTokenTTL.Seconds()),
		Message:      "Token refreshed successfully",
		SessionID:    newSessionID,
		Data:         responseData,
	}, nil
}
