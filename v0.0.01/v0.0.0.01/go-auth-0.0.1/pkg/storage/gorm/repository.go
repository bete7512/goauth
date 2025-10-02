package gorm

import (
	"context"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/storage"
	"gorm.io/gorm"
)

// GenericRepository implements the Repository interface
type GenericRepository struct {
	db    *gorm.DB
	model interface{}
}

func NewGenericRepository(db *gorm.DB, model interface{}) *GenericRepository {
	return &GenericRepository{
		db:    db,
		model: model,
	}
}

func (r *GenericRepository) Create(ctx context.Context, entity interface{}) error {
	return r.db.WithContext(ctx).Create(entity).Error
}

func (r *GenericRepository) FindByID(ctx context.Context, id interface{}, dest interface{}) error {
	return r.db.WithContext(ctx).First(dest, id).Error
}

func (r *GenericRepository) FindOne(ctx context.Context, query interface{}, dest interface{}) error {
	if qb, ok := query.(*storage.QueryBuilder); ok {
		return r.applyQueryBuilder(r.db.WithContext(ctx), qb).First(dest).Error
	}
	return r.db.WithContext(ctx).Where(query).First(dest).Error
}

func (r *GenericRepository) FindAll(ctx context.Context, query interface{}, dest interface{}) error {
	if qb, ok := query.(*storage.QueryBuilder); ok {
		return r.applyQueryBuilder(r.db.WithContext(ctx), qb).Find(dest).Error
	}
	return r.db.WithContext(ctx).Where(query).Find(dest).Error
}

func (r *GenericRepository) Update(ctx context.Context, entity interface{}) error {
	return r.db.WithContext(ctx).Save(entity).Error
}

func (r *GenericRepository) Delete(ctx context.Context, entity interface{}) error {
	return r.db.WithContext(ctx).Delete(entity).Error
}

func (r *GenericRepository) Count(ctx context.Context, query interface{}) (int64, error) {
	var count int64
	db := r.db.WithContext(ctx).Model(r.model)

	if qb, ok := query.(*storage.QueryBuilder); ok {
		db = r.applyQueryBuilder(db, qb)
	} else if query != nil {
		db = db.Where(query)
	}

	err := db.Count(&count).Error
	return count, err
}

func (r *GenericRepository) applyQueryBuilder(db *gorm.DB, qb *storage.QueryBuilder) *gorm.DB {
	// Apply conditions
	for field, value := range qb.Conditions {
		db = db.Where(fmt.Sprintf("%s = ?", field), value)
	}

	// Apply ordering
	for _, order := range qb.OrderBy {
		db = db.Order(order)
	}

	// Apply limit
	if qb.Limit > 0 {
		db = db.Limit(qb.Limit)
	}

	// Apply offset
	if qb.Offset > 0 {
		db = db.Offset(qb.Offset)
	}

	// Apply preloads
	for _, preload := range qb.Preload {
		db = db.Preload(preload)
	}

	return db
}

// UserRepository implements the UserRepository interface
type UserRepository struct {
	*GenericRepository
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		GenericRepository: &GenericRepository{db: db},
	}
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string, dest interface{}) error {
	return r.db.WithContext(ctx).Where("email = ?", email).First(dest).Error
}

func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(r.model).Where("email = ?", email).Count(&count).Error
	return count > 0, err
}

// SessionRepository implements the SessionRepository interface
type SessionRepository struct {
	*GenericRepository
}

func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{
		GenericRepository: &GenericRepository{db: db},
	}
}

func (r *SessionRepository) FindByToken(ctx context.Context, token string, dest interface{}) error {
	return r.db.WithContext(ctx).Where("token = ?", token).First(dest).Error
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(r.model).Error
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(r.model).Error
}
