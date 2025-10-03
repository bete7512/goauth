package storage

import "context"

// all modules models repositories interfaces should be inported and have to be implemented from all storage supported

type CustomStorage interface {
	Create(ctx context.Context, entity interface{}) error
	FindByID(ctx context.Context, id interface{}, dest interface{}) error
	FindOne(ctx context.Context, query interface{}, dest interface{}) error
	FindAll(ctx context.Context, query interface{}, dest interface{}) error
	Update(ctx context.Context, entity interface{}) error
	Delete(ctx context.Context, entity interface{}) error
	Count(ctx context.Context, query interface{}) (int64, error)
}

