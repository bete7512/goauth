package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/session/services"
	"github.com/bete7512/goauth/internal/security/cookie"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type ValidatorSuite struct {
	suite.Suite
	ctrl        *gomock.Controller
	sessionRepo *mocks.MockSessionRepository
	encoder     cookie.CookieEncoder
	validator   *services.SessionValidator
}

func TestValidatorSuite(t *testing.T) {
	suite.Run(t, new(ValidatorSuite))
}

func (s *ValidatorSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.sessionRepo = mocks.NewMockSessionRepository(s.ctrl)
	s.encoder = cookie.NewEncoder("compact", "test-key-for-validator")
	s.validator = services.NewSessionValidator(s.encoder, s.sessionRepo, services.ValidatorConfig{
		CacheTTL:          5 * time.Minute,
		SessionTTL:        24 * time.Hour,
		SensitivePaths:    []string{"/admin/*", "/settings/security"},
		SlidingExpiration: false,
		UpdateAge:         10 * time.Minute,
	})
}

func (s *ValidatorSuite) TearDownTest() {
	s.ctrl.Finish()
}

// --- ValidateFromCookie ---

func (s *ValidatorSuite) TestValidateFromCookie_Valid() {
	cookieVal, err := s.validator.BuildCookieValue("sess-1", "user-1")
	s.NoError(err)

	result := s.validator.ValidateFromCookie(cookieVal)
	s.True(result.Valid)
	s.Equal("sess-1", result.SessionID)
	s.Equal("user-1", result.UserID)
	s.Equal("cookie", result.Source)
	s.False(result.ShouldRefresh)
	s.Nil(result.Error)
}

func (s *ValidatorSuite) TestValidateFromCookie_Empty() {
	result := s.validator.ValidateFromCookie("")
	s.False(result.Valid)
	s.True(result.ShouldRefresh)
	s.NotNil(result.Error)
}

func (s *ValidatorSuite) TestValidateFromCookie_DecodeError() {
	result := s.validator.ValidateFromCookie("garbage-value")
	s.False(result.Valid)
	s.True(result.ShouldRefresh)
	s.NotNil(result.Error)
}

func (s *ValidatorSuite) TestValidateFromCookie_UpdateAgeExceeded() {
	// Encode with IssuedAt 20 minutes ago (> UpdateAge of 10m)
	cookieVal, err := s.encoder.Encode(&types.SessionCookieData{
		SessionID: "sess-old",
		UserID:    "user-old",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Add(-20 * time.Minute).Unix(),
	})
	s.NoError(err)

	result := s.validator.ValidateFromCookie(cookieVal)
	s.False(result.Valid, "should not trust stale cookie")
	s.True(result.ShouldRefresh, "should trigger DB re-check")
}

func (s *ValidatorSuite) TestValidateFromCookie_UpdateAgeNotExceeded() {
	// Build cookie with recent IssuedAt
	cookieVal, err := s.validator.BuildCookieValue("sess-fresh", "user-fresh")
	s.NoError(err)

	result := s.validator.ValidateFromCookie(cookieVal)
	s.True(result.Valid)
	s.False(result.ShouldRefresh)
}

// --- ValidateFromDB ---

func (s *ValidatorSuite) TestValidateFromDB_Found() {
	session := &models.Session{
		ID:        "sess-db",
		UserID:    "user-db",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	s.sessionRepo.EXPECT().FindByID(gomock.Any(), "sess-db").Return(session, nil)

	result := s.validator.ValidateFromDB(context.Background(), "sess-db")
	s.True(result.Valid)
	s.Equal("sess-db", result.SessionID)
	s.Equal("user-db", result.UserID)
	s.True(result.ShouldRefresh)
	s.Equal("database", result.Source)
	s.Nil(result.Error)
}

func (s *ValidatorSuite) TestValidateFromDB_NotFound() {
	s.sessionRepo.EXPECT().FindByID(gomock.Any(), "sess-gone").Return(nil, nil)

	result := s.validator.ValidateFromDB(context.Background(), "sess-gone")
	s.False(result.Valid)
	s.ErrorIs(result.Error, services.ErrSessionRevoked)
}

func (s *ValidatorSuite) TestValidateFromDB_Expired() {
	session := &models.Session{
		ID:        "sess-expired",
		UserID:    "user-expired",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	s.sessionRepo.EXPECT().FindByID(gomock.Any(), "sess-expired").Return(session, nil)

	result := s.validator.ValidateFromDB(context.Background(), "sess-expired")
	s.False(result.Valid)
	s.ErrorIs(result.Error, services.ErrSessionRevoked)
}

func (s *ValidatorSuite) TestValidateFromDB_SlidingExtensionTriggers() {
	// Create validator with sliding expiration enabled
	v := services.NewSessionValidator(s.encoder, s.sessionRepo, services.ValidatorConfig{
		CacheTTL:          5 * time.Minute,
		SessionTTL:        24 * time.Hour,
		SlidingExpiration: true,
		UpdateAge:         10 * time.Minute,
	})

	// Session expires in 3 minutes (< UpdateAge/2 = 5 minutes)
	session := &models.Session{
		ID:        "sess-extend",
		UserID:    "user-extend",
		ExpiresAt: time.Now().Add(3 * time.Minute),
		UpdatedAt: time.Now().Add(-8 * time.Minute),
	}
	s.sessionRepo.EXPECT().FindByID(gomock.Any(), "sess-extend").Return(session, nil)
	s.sessionRepo.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, sess *models.Session) error {
		// Verify session was extended
		s.True(sess.ExpiresAt.After(time.Now().Add(23*time.Hour)), "ExpiresAt should be extended by SessionTTL")
		return nil
	})

	result := v.ValidateFromDB(context.Background(), "sess-extend")
	s.True(result.Valid)
	s.True(result.ShouldRefresh)
}

func (s *ValidatorSuite) TestValidateFromDB_SlidingExtensionDoesNotTrigger() {
	// Create validator with sliding expiration enabled
	v := services.NewSessionValidator(s.encoder, s.sessionRepo, services.ValidatorConfig{
		CacheTTL:          5 * time.Minute,
		SessionTTL:        24 * time.Hour,
		SlidingExpiration: true,
		UpdateAge:         10 * time.Minute,
	})

	// Session expires in 20 minutes (> UpdateAge/2 = 5 minutes) — no extension
	session := &models.Session{
		ID:        "sess-no-extend",
		UserID:    "user-no-extend",
		ExpiresAt: time.Now().Add(20 * time.Minute),
	}
	s.sessionRepo.EXPECT().FindByID(gomock.Any(), "sess-no-extend").Return(session, nil)
	// Note: no Update expectation — should not be called

	result := v.ValidateFromDB(context.Background(), "sess-no-extend")
	s.True(result.Valid)
	s.True(result.ShouldRefresh) // Always true after DB validation
}

// --- IsSensitivePath ---

func (s *ValidatorSuite) TestIsSensitivePath_ExactMatch() {
	s.True(s.validator.IsSensitivePath("/settings/security"))
}

func (s *ValidatorSuite) TestIsSensitivePath_WildcardMatch() {
	s.True(s.validator.IsSensitivePath("/admin/users"))
	s.True(s.validator.IsSensitivePath("/admin/users/123"))
	s.True(s.validator.IsSensitivePath("/admin"))
}

func (s *ValidatorSuite) TestIsSensitivePath_NoMatch() {
	s.False(s.validator.IsSensitivePath("/api/users"))
	s.False(s.validator.IsSensitivePath("/settings/profile"))
}

// --- BuildCookieValue ---

func (s *ValidatorSuite) TestBuildCookieValue() {
	cookieVal, err := s.validator.BuildCookieValue("sess-build", "user-build")
	s.NoError(err)
	s.NotEmpty(cookieVal)

	// Verify we can decode it back
	result := s.validator.ValidateFromCookie(cookieVal)
	s.True(result.Valid)
	s.Equal("sess-build", result.SessionID)
	s.Equal("user-build", result.UserID)
}

// --- CacheTTL ---

func (s *ValidatorSuite) TestCacheTTL() {
	s.Equal(5*time.Minute, s.validator.CacheTTL())
}
