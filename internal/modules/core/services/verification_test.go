package core_services_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	core_services "github.com/bete7512/goauth/internal/modules/core/services"
	"github.com/bete7512/goauth/internal/testutil"
	"github.com/bete7512/goauth/pkg/config"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type VerificationServiceSuite struct {
	suite.Suite
}

func TestVerificationServiceSuite(t *testing.T) {
	suite.Run(t, new(VerificationServiceSuite))
}

func (s *VerificationServiceSuite) setupService() (core_services.CoreService, *mocks.MockUserRepository, *mocks.MockTokenRepository) {
	ctrl := gomock.NewController(s.T())
	s.T().Cleanup(ctrl.Finish)

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTokenRepo := mocks.NewMockTokenRepository(ctrl)
	mockLogger := mocks.NewMockLogger(ctrl)

	coreStore := mocks.NewMockCoreStorage(ctrl)
	coreStore.EXPECT().Users().Return(mockUserRepo).AnyTimes()
	coreStore.EXPECT().Tokens().Return(mockTokenRepo).AnyTimes()
	coreStore.EXPECT().WithTransaction(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, fn func(types.CoreStorage) error) error { return fn(coreStore) }).AnyTimes()
	secMgr := testutil.TestSecurityManager()

	deps := config.ModuleDependencies{
		Storage:         &types.StorageSet{CoreStore: coreStore},
		Config:          testutil.TestConfig(),
		Events:          mocks.NewMockEventBus(ctrl),
		Logger:          mockLogger,
		SecurityManager: secMgr,
	}
	svc := core_services.NewCoreService(deps, mockUserRepo, mockTokenRepo, mockLogger, secMgr, testutil.TestCoreConfig())
	return svc, mockUserRepo, mockTokenRepo
}

func (s *VerificationServiceSuite) TestVerifyPhone() {
	const phone = "+15550001001"
	user := testutil.TestUser()
	user.PhoneNumber = phone
	newToken := func(attempts int) *models.Token {
		tok := testutil.TestVerificationToken(user.ID, models.TokenTypePhoneVerification)
		tok.PhoneNumber = phone
		tok.Attempts = attempts
		return tok
	}

	tests := []struct {
		name       string
		code       string
		setup      func(*mocks.MockUserRepository, *mocks.MockTokenRepository)
		wantErr    bool
		errCode    types.ErrorCode
		wantStatus int
	}{
		{
			name: "success",
			code: "123456",
			setup: func(ur *mocks.MockUserRepository, tr *mocks.MockTokenRepository) {
				tok := newToken(0)
				tr.EXPECT().FindByPhoneAndType(gomock.Any(), phone, models.TokenTypePhoneVerification).Return(tok, nil)
				ur.EXPECT().FindByPhoneNumber(gomock.Any(), phone).Return(user, nil)
				tr.EXPECT().MarkAsUsed(gomock.Any(), tok.ID).Return(nil)
				ur.EXPECT().Update(gomock.Any(), gomock.AssignableToTypeOf(&models.User{})).Return(nil)
			},
		},
		{
			name: "wrong code counts an attempt",
			code: "000000",
			setup: func(_ *mocks.MockUserRepository, tr *mocks.MockTokenRepository) {
				tok := newToken(0)
				tr.EXPECT().FindByPhoneAndType(gomock.Any(), phone, models.TokenTypePhoneVerification).Return(tok, nil)
				tr.EXPECT().IncrementAttempts(gomock.Any(), tok.ID).Return(1, nil)
			},
			wantErr:    true,
			errCode:    types.ErrInvalidToken,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "last wrong code consumes the token",
			code: "000000",
			setup: func(_ *mocks.MockUserRepository, tr *mocks.MockTokenRepository) {
				tok := newToken(4)
				tr.EXPECT().FindByPhoneAndType(gomock.Any(), phone, models.TokenTypePhoneVerification).Return(tok, nil)
				tr.EXPECT().IncrementAttempts(gomock.Any(), tok.ID).Return(5, nil)
				tr.EXPECT().MarkAsUsed(gomock.Any(), tok.ID).Return(nil)
			},
			wantErr:    true,
			errCode:    types.ErrInvalidToken,
			wantStatus: http.StatusTooManyRequests,
		},
		{
			name: "exhausted code rejects the right value",
			code: "123456",
			setup: func(_ *mocks.MockUserRepository, tr *mocks.MockTokenRepository) {
				tr.EXPECT().FindByPhoneAndType(gomock.Any(), phone, models.TokenTypePhoneVerification).Return(newToken(5), nil)
			},
			wantErr:    true,
			errCode:    types.ErrInvalidToken,
			wantStatus: http.StatusTooManyRequests,
		},
		{
			name: "no live code for the phone",
			code: "123456",
			setup: func(_ *mocks.MockUserRepository, tr *mocks.MockTokenRepository) {
				tr.EXPECT().FindByPhoneAndType(gomock.Any(), phone, models.TokenTypePhoneVerification).Return(nil, models.ErrNotFound)
			},
			wantErr:    true,
			errCode:    types.ErrInvalidToken,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, mockTokenRepo := s.setupService()
			tt.setup(mockUserRepo, mockTokenRepo)

			resp, goauthErr := svc.VerifyPhone(context.Background(), tt.code, phone)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
				if tt.wantStatus != 0 {
					s.Equal(tt.wantStatus, goauthErr.StatusCode)
				}
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
			}
		})
	}
}
