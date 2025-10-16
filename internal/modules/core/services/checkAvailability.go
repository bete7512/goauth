package core_services

import (
	"context"
)

func (s *CoreService) CheckEmailAvailability(ctx context.Context, email string) (bool, error) {
	s.Logger.Info("Checking email availability", "email", email)
	return s.UserRepository.IsAvailable(ctx, "email", email)
}

func (s *CoreService) CheckUsernameAvailability(ctx context.Context, username string) (bool, error) {
	s.Logger.Info("Checking username availability", "username", username)
	return s.UserRepository.IsAvailable(ctx, "username", username)
}

func (s *CoreService) CheckPhoneAvailability(ctx context.Context, phone string) (bool, error) {
	s.Logger.Info("Checking phone availability", "phone", phone)
	return s.UserRepository.IsAvailable(ctx, "phone", phone)
}
