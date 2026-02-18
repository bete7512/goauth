package core_services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bete7512/goauth/internal/mocks"
	"github.com/bete7512/goauth/internal/modules/core/handlers/dto"
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

func (s *CheckAvailabilitySuite) TestCheckAvailability() {
	tests := []struct {
		name      string
		req       *dto.CheckAvailabilityRequest
		setup     func(*mocks.MockUserRepository)
		wantAvail bool
		wantField string
		wantErr   bool
		errCode   types.ErrorCode
	}{
		{
			name: "email available",
			req:  &dto.CheckAvailabilityRequest{Email: "new@example.com"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "email", "new@example.com").Return(true, nil)
			},
			wantAvail: true,
			wantField: "email",
		},
		{
			name: "email taken",
			req:  &dto.CheckAvailabilityRequest{Email: "taken@example.com"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "email", "taken@example.com").Return(false, nil)
			},
			wantAvail: false,
			wantField: "email",
		},
		{
			name: "username available",
			req:  &dto.CheckAvailabilityRequest{Username: "newuser"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "username", "newuser").Return(true, nil)
			},
			wantAvail: true,
			wantField: "username",
		},
		{
			name: "username taken",
			req:  &dto.CheckAvailabilityRequest{Username: "takenuser"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "username", "takenuser").Return(false, nil)
			},
			wantAvail: false,
			wantField: "username",
		},
		{
			name: "phone available",
			req:  &dto.CheckAvailabilityRequest{Phone: "+1234567890"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "phone_number", "+1234567890").Return(true, nil)
			},
			wantAvail: true,
			wantField: "phone",
		},
		{
			name: "phone taken",
			req:  &dto.CheckAvailabilityRequest{Phone: "+0987654321"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "phone_number", "+0987654321").Return(false, nil)
			},
			wantAvail: false,
			wantField: "phone",
		},
		{
			name: "db error",
			req:  &dto.CheckAvailabilityRequest{Email: "test@example.com"},
			setup: func(ur *mocks.MockUserRepository) {
				ur.EXPECT().IsAvailable(gomock.Any(), "email", "test@example.com").Return(false, errors.New("db error"))
			},
			wantErr: true,
			errCode: types.ErrInternalError,
		},
		{
			name:    "no field provided",
			req:     &dto.CheckAvailabilityRequest{},
			setup:   func(_ *mocks.MockUserRepository) {},
			wantErr: true,
			errCode: types.ErrInvalidRequestBody,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			svc, mockUserRepo, _, _ := (&PasswordServiceSuite{Suite: s.Suite}).setupService()
			tt.setup(mockUserRepo)

			resp, goauthErr := svc.CheckAvailability(context.Background(), tt.req)

			if tt.wantErr {
				s.Nil(resp)
				s.NotNil(goauthErr)
				s.Equal(tt.errCode, goauthErr.Code)
			} else {
				s.Nil(goauthErr)
				s.NotNil(resp)
				s.Equal(tt.wantAvail, resp.Available)
				s.Equal(tt.wantField, resp.Field)
			}
		})
	}
}
