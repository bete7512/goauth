package services

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/bete7512/goauth/internal/modules/stateless/handlers/dto"
	"github.com/bete7512/goauth/internal/security"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/google/uuid"
)

// Refresh refreshes tokens using JWT refresh token with nonce validation
func (s *StatelessService) Refresh(ctx context.Context, req *dto.RefreshRequest) (dto.AuthResponse, *types.GoAuthError) {
	// Parse and validate JWT refresh token
	claims, err := security.ValidateCredential(s.SecurityManager, req.RefreshToken, "refresh")
	if err != nil {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Verify token type
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Get JTI (nonce)
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Get User ID
	userID, ok := claims["user_id"].(string)
	if !ok || userID == "" {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Check if JTI exists in database (is valid and not blacklisted/revoked)
	previous, err := s.TokenRepository.FindByToken(ctx, jti)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			// If not found, it means it's revoked or never existed
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to find token record").Wrap(err)
	}
	if previous.UserID != userID || previous.Type != "refresh_nonce" || previous.Used || !time.Now().Before(previous.ExpiresAt) {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	// Check if user exists
	user, err := s.UserRepository.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to find user").Wrap(err)
	}

	if authErr := security.CheckEligibility(user, s.Deps.Config.Core); authErr != nil {
		return dto.AuthResponse{}, authErr
	}
	if version, ok := claims["token_version"].(float64); !ok || version != float64(user.TokenVersion) {
		return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
	}

	var grant types.GrantContext
	if previous.Data != "" {
		if err := json.Unmarshal([]byte(previous.Data), &grant); err != nil {
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
	}
	if grant.AuthenticatedAt.IsZero() {
		grant.AuthenticatedAt = previous.CreatedAt
	}
	// Reevaluate policy using persisted grant context.
	interceptClaims, challenges, responseData, interceptErr := s.Deps.AuthInterceptors.Run(ctx, &types.InterceptParams{
		Phase:           types.PhaseRefresh,
		User:            user,
		VerifiedMethods: grant.Methods,
		ExistingClaims:  map[string]interface{}{"active_org_id": grant.OrganizationID},
	})
	if interceptErr != nil {
		return dto.AuthResponse{}, types.NewInternalError("Token refresh interrupted")
	}
	if len(challenges) > 0 && s.Deps.Completion != nil {
		result, authErr := s.Deps.Completion.Complete(ctx, types.AuthenticationEvidence{User: user, Method: "refresh", Phase: types.PhaseRefresh, Methods: grant.Methods, AuthenticatedAt: grant.AuthenticatedAt, Claims: map[string]interface{}{"active_org_id": grant.OrganizationID}})
		if authErr != nil {
			return dto.AuthResponse{}, authErr
		}
		return dto.AuthResponse{Challenges: result.Challenges, Message: "Authentication challenge required"}, nil
	}
	if len(challenges) > 0 {
		return dto.AuthResponse{Challenges: challenges, Message: "Authentication challenge required"}, nil
	}

	interceptClaims["auth_time"] = grant.AuthenticatedAt.Unix()
	interceptClaims["amr"] = grant.Methods
	// Generate new access token with enriched claims
	accessToken, err := s.SecurityManager.GenerateAccessToken(
		*user,
		interceptClaims,
	)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to generate access token").Wrap(err)
	}

	// Generate new refresh token with new JTI
	newRefreshToken, newJti, err := s.SecurityManager.GenerateStatelessRefreshToken(user)
	if err != nil {
		return dto.AuthResponse{}, types.NewInternalError("failed to generate refresh token").Wrap(err)
	}

	// Save new nonce
	tokenModel := &models.Token{
		Data:      previous.Data,
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		Type:      "refresh_nonce",
		Token:     newJti,
		ExpiresAt: previous.ExpiresAt,
		CreatedAt: time.Now(),
	}
	rotator, ok := s.TokenRepository.(models.TokenRotator)
	if !ok {
		return dto.AuthResponse{}, types.NewInternalError("token storage requires atomic rotation")
	}
	if err := rotator.Rotate(ctx, previous, tokenModel); err != nil {
		if errors.Is(err, models.ErrConflict) {
			return dto.AuthResponse{}, types.NewInvalidRefreshTokenError()
		}
		return dto.AuthResponse{}, types.NewInternalError("failed to save refresh token nonce").Wrap(err)
	}

	return dto.AuthResponse{
		AccessToken:  &accessToken,
		RefreshToken: &newRefreshToken,
		ExpiresIn:    int64(s.Deps.Config.Security.Session.AccessTokenTTL.Seconds()),
		Message:      "Token refreshed successfully",
		Data:         responseData,
	}, nil
}
