package main

import (
	"context"

	"github.com/bete7512/goauth/pkg/models"
	"github.com/bete7512/goauth/pkg/types"
)

type sessionStorage struct {
}

type sessionRepository struct {
}

func (s *sessionStorage) Sessions() models.SessionRepository {
	return &sessionRepository{}
}

func (s *sessionStorage) WithTransaction(ctx context.Context, fn func(tx types.SessionStorage) error) error {
	return fn(s)
}

func (s *sessionRepository) Create(ctx context.Context, session *models.Session) error {
	return nil
}

func (s *sessionRepository) FindByID(ctx context.Context, id string) (*models.Session, error) {
	return nil, nil
}

func (s *sessionRepository) FindByToken(ctx context.Context, token string) (*models.Session, error) {
	return nil, nil
}

func (s *sessionRepository) FindByUserID(ctx context.Context, userID string, opts models.SessionListOpts) ([]*models.Session, int64, error) {
	return nil, 0, nil
}

func (s *sessionRepository) Update(ctx context.Context, session *models.Session) error {
	return nil
}

func (s *sessionRepository) Delete(ctx context.Context, id string) error {
	return nil
}

func (s *sessionRepository) DeleteByToken(ctx context.Context, token string) error {
	return nil
}

func (s *sessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return nil
}

func (s *sessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	return 0, nil
}
