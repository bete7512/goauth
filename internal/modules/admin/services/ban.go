package services

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

// maxBanReason matches the ban_reason column.
const maxBanReason = 500

// BanInput describes a ban. A zero Until bans until an administrator lifts
// it.
type BanInput struct {
	Reason string
	Until  time.Time
}

// Ban suspends a user: they cannot sign in, and every credential they hold
// is revoked, so the ban takes effect at once. A ban with an end lifts
// itself then. Administrators cannot ban themselves.
func (s *adminService) Ban(ctx context.Context, userID string, input BanInput) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	if actor.ID == userID {
		return types.NewValidationError("you cannot ban your own account")
	}
	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		return types.NewValidationError("give a reason for the ban; it is recorded for other administrators")
	}
	if utf8.RuneCountInString(reason) > maxBanReason || len(reason) > maxBanReason {
		return types.NewValidationError("the reason must be at most 500 characters")
	}
	now := time.Now().UTC()
	if !input.Until.IsZero() && !input.Until.After(now) {
		return types.NewValidationError("the end of the ban must be in the future")
	}
	user, err := s.userRepository.FindByID(ctx, userID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && user == nil) {
		return types.NewUserNotFoundError()
	}
	if err != nil {
		return types.NewInternalError("failed to load user").Wrap(err)
	}
	user.BannedAt = &now
	user.BannedUntil = nil
	if !input.Until.IsZero() {
		until := input.Until.UTC()
		user.BannedUntil = &until
	}
	user.BanReason = reason
	user.UpdatedAt = &now
	if err := s.userRepository.Update(ctx, user); err != nil {
		return types.NewInternalError("failed to ban user").Wrap(err)
	}
	// The ban already makes every credential fail its eligibility check;
	// revoking them as well means lifting the ban does not revive them.
	if authErr := s.revokeAll(ctx, userID); authErr != nil {
		return authErr
	}
	details := "Banned until lifted: " + reason
	if user.BannedUntil != nil {
		details = "Banned until " + user.BannedUntil.Format(time.RFC3339) + ": " + reason
	}
	s.securityEvent(ctx, actor.ID, userID, details)
	return nil
}

// Unban lifts a ban before it ends.
func (s *adminService) Unban(ctx context.Context, userID string) *types.GoAuthError {
	actor, authErr := s.authorize(ctx)
	if authErr != nil {
		return authErr
	}
	user, err := s.userRepository.FindByID(ctx, userID)
	if errors.Is(err, models.ErrNotFound) || (err == nil && user == nil) {
		return types.NewUserNotFoundError()
	}
	if err != nil {
		return types.NewInternalError("failed to load user").Wrap(err)
	}
	if user.BannedAt == nil {
		return nil
	}
	now := time.Now().UTC()
	user.BannedAt, user.BannedUntil, user.BanReason, user.UpdatedAt = nil, nil, "", &now
	if err := s.userRepository.Update(ctx, user); err != nil {
		return types.NewInternalError("failed to lift the ban").Wrap(err)
	}
	s.securityEvent(ctx, actor.ID, userID, "Lifted the ban")
	return nil
}
