package core_services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/pkg/types"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type CheckAvailabilitySuite struct {
	suite.Suite
}

func TestCheckAvailabilitySuite(t *testing.T) {
	suite.Run(t, new(CheckAvailabilitySuite))
}

func (s *CheckAvailabilitySuite) TestCheckEmailAvailability() {
	tests := []struct {
		name      string
		email     string
		setup     func(*mocks.MockUserRepository)
		wantAvail bool
		wantErr   bool
		errCode   types.ErrorCode
	}{
		{
			name:  "available",
			email: "new@example.com",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "email", "new@example.com").Return(true, nil)
			},
			wantAvail: true,
		},
		{
			name:  "taken",
			email: "taken@example.com",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "email", "taken@example.com").Return(false, nil)
			},
			wantAvail: false,
		},
		{
			name:  "db error",
			email: "test@example.com",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "email", "test@example.com").Return(false, errors.New("db error"))
			},
			wantErr: true,
			errCode: types.ErrInternalError,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, _, _ := (&PasswordServiceSuite{Suite: s.Suite}).setupService()
			tt.setup(mockUserRepo)

			resp, goauthErr := svc.CheckEmailAvailability(context.Background(), tt.email)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
				s.Equal(tt.wantAvail, resp.Available)
			}
		})
	}
}

func (s *CheckAvailabilitySuite) TestCheckUsernameAvailability() {
	tests := []struct {
		name      string
		username  string
		setup     func(*mocks.MockUserRepository)
		wantAvail bool
	}{
		{
			name:     "available",
			username: "newuser",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "username", "newuser").Return(true, nil)
			},
			wantAvail: true,
		},
		{
			name:     "taken",
			username: "takenuser",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "username", "takenuser").Return(false, nil)
			},
			wantAvail: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, _, _ := (&PasswordServiceSuite{Suite: s.Suite}).setupService()
			tt.setup(mockUserRepo)

			resp, goauthErr := svc.CheckUsernameAvailability(context.Background(), tt.username)

			s.Nil(goauthErr)
			s.NotNil(resp)
			s.Equal(tt.wantAvail, resp.Available)
		})
	}
}

func (s *CheckAvailabilitySuite) TestCheckPhoneAvailability() {
	tests := []struct {
		name      string
		phone     string
		setup     func(*mocks.MockUserRepository)
		wantAvail bool
	}{
		{
			name:  "available",
			phone: "+1234567890",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "phone_number", "+1234567890").Return(true, nil)
			},
			wantAvail: true,
		},
		{
			name:  "taken",
			phone: "+0987654321",
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "phone_number", "+0987654321").Return(false, nil)
			},
			wantAvail: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, _, _ := (&PasswordServiceSuite{Suite: s.Suite}).setupService()
			tt.setup(mockUserRepo)

			resp, goauthErr := svc.CheckPhoneAvailability(context.Background(), tt.phone)

			s.Nil(goauthErr)
			s.NotNil(resp)
			s.Equal(tt.wantAvail, resp.Available)
		})
	}
}
