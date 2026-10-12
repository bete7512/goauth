package services_test

import (
	"context"
	"testing"
	"time"

	"github.com/bete7512/goauth/internal/interceptor"
	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/passkeys/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type PasskeyServiceSuite struct {
	suite.Suite
}

func TestPasskeyServiceSuite(t *testing.T) {
	suite.Run(t, new(PasskeyServiceSuite))
}

func (s *PasskeyServiceSuite) setupService() (
	services.PasskeyService,
	*mocks.MockPasskeyRepository,
	*mocks.MockUserRepository,
) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockPasskeys := mocks.NewMockPasskeyRepository(ctrl)
	mockUsers := mocks.NewMockUserRepository(ctrl)

	secMgr := testutil.TestSecurityManager()

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "GoAuth Test",
		RPOrigins:     []string{"https://example.com"},
	})
	s.Require().NoError(err)

	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	tokenRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	coreStore := mocks.NewMockCoreStorage(ctrl)
	coreStore.EXPECT().Tokens().Return(tokenRepo).AnyTimes()
	store := mocks.NewMockStorage(ctrl)
	store.EXPECT().Core().Return(coreStore).AnyTimes()
	deps := config.ModuleDependencies{
		Storage:          store,
		Config:           testutil.TestConfig(),
		SecurityManager:  secMgr,
		Logger:           mocks.NewMockLogger(ctrl),
		AuthInterceptors: interceptor.NewRegistry(),
	}

	cfg := &config.PasskeysModuleConfig{
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
		RPDisplayName: "GoAuth Test",
	}

	svc := services.NewPasskeyService(deps, cfg, wa, mockPasskeys, mockUsers, secMgr)
	return svc, mockPasskeys, mockUsers
}

// Registration-begin returns a challenge token the client echoes back on finish.
// We can't execute a real attestation without a browser authenticator, but we
// can at least confirm the ceremony setup completes and the payload is shaped.
func (s *PasskeyServiceSuite) TestBeginRegistration_ReturnsChallengeAndOptions() {
	svc, mockPasskeys, mockUsers := s.setupService()

	user := testutil.TestUser()
	mockUsers.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	mockPasskeys.EXPECT().ListByUserID(gomock.Any(), user.ID).Return(nil, nil)

	resp, authErr := svc.BeginRegistration(context.Background(), user.ID)
	s.Nil(authErr)
	s.Require().NotNil(resp)
	s.NotEmpty(resp.ChallengeToken, "challenge token must be sealed and returned")
	s.NotEmpty(resp.PublicKey.Challenge, "public key options must include a challenge")
	s.Equal("example.com", resp.PublicKey.RelyingParty.ID)
}

func (s *PasskeyServiceSuite) TestBeginLogin_DiscoverableFlow() {
	svc, _, _ := s.setupService()

	resp, authErr := svc.BeginLogin(context.Background())
	s.Nil(authErr)
	s.Require().NotNil(resp)
	s.NotEmpty(resp.ChallengeToken)
	s.NotEmpty(resp.PublicKey.Challenge)
	// Discoverable login must not enumerate credentials in the response.
	s.Empty(resp.PublicKey.AllowedCredentials)
}

func (s *PasskeyServiceSuite) TestListCredentials_EmptyAndNonEmpty() {
	svc, mockPasskeys, _ := s.setupService()

	mockPasskeys.EXPECT().ListByUserID(gomock.Any(), "u1").Return(nil, nil)
	items, authErr := svc.ListCredentials(context.Background(), "u1")
	s.Nil(authErr)
	s.Empty(items)

	now := time.Now()
	stored := []*models.PasskeyCredential{{
		ID:         "p1",
		UserID:     "u1",
		Name:       "My iPhone",
		Transports: "internal,hybrid",
		CreatedAt:  now,
	}}
	mockPasskeys.EXPECT().ListByUserID(gomock.Any(), "u1").Return(stored, nil)
	items, authErr = svc.ListCredentials(context.Background(), "u1")
	s.Nil(authErr)
	s.Len(items, 1)
	s.Equal("My iPhone", items[0].Name)
	s.Equal([]string{"internal", "hybrid"}, items[0].Transports)
}

func (s *PasskeyServiceSuite) TestDeleteCredential_ForbidsOtherUsers() {
	svc, mockPasskeys, _ := s.setupService()

	other := &models.PasskeyCredential{ID: "p1", UserID: "other"}
	mockPasskeys.EXPECT().FindByID(gomock.Any(), "p1").Return(other, nil)

	authErr := svc.DeleteCredential(context.Background(), "u1", "p1")
	s.Require().NotNil(authErr)
	s.Equal(types.ErrForbidden, authErr.Code)
}

func (s *PasskeyServiceSuite) TestDeleteCredential_Success() {
	svc, mockPasskeys, _ := s.setupService()

	owned := &models.PasskeyCredential{ID: "p1", UserID: "u1"}
	mockPasskeys.EXPECT().FindByID(gomock.Any(), "p1").Return(owned, nil)
	mockPasskeys.EXPECT().Delete(gomock.Any(), "p1").Return(nil)

	authErr := svc.DeleteCredential(context.Background(), "u1", "p1")
	s.Nil(authErr)
}

func (s *PasskeyServiceSuite) TestRenameCredential_NotFound() {
	svc, mockPasskeys, _ := s.setupService()

	mockPasskeys.EXPECT().FindByID(gomock.Any(), "missing").Return(nil, models.ErrNotFound)

	authErr := svc.RenameCredential(context.Background(), "u1", "missing", "new")
	s.Require().NotNil(authErr)
	s.Equal(types.ErrPasskeyNotFound, authErr.Code)
}
