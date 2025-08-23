package mongodb

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AuditLogRepository struct {
	client *mongo.Client
}

func NewAuditLogRepository(client *mongo.Client) interfaces.AuditLogRepository {
	return &AuditLogRepository{client: client}
}

func (a *AuditLogRepository) SaveAuditLog(ctx context.Context, log *models.AuditLog) error {
	collection := a.client.Database("goauth").Collection("audit_logs")

	_, err := collection.InsertOne(ctx, log)
	if err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}
	return nil
}

func (a *AuditLogRepository) GetAuditLogs(ctx context.Context, filter interfaces.Filter) ([]*models.AuditLog, int64, error) {
	collection := a.client.Database("goauth").Collection("audit_logs")

	// Count total
	total, err := collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Build options for pagination and sorting
	opts := options.Find()
	if filter.Page > 0 && filter.Limit > 0 {
		skip := int64((filter.Page - 1) * filter.Limit)
		limit := int64(filter.Limit)
		opts.SetSkip(skip).SetLimit(limit)
	}
	if filter.Sort.Field != "" {
		direction := 1
		if filter.Sort.Direction == "desc" {
			direction = -1
		}
		opts.SetSort(bson.D{{Key: filter.Sort.Field, Value: direction}})
	}

	// Find audit logs
	cursor, err := collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get audit logs: %w", err)
	}
	defer cursor.Close(ctx)

	var logs []*models.AuditLog
	if err = cursor.All(ctx, &logs); err != nil {
		return nil, 0, fmt.Errorf("failed to decode audit logs: %w", err)
	}

	return logs, total, nil
}

func (a *AuditLogRepository) GetAuditLogByID(ctx context.Context, id string) (*models.AuditLog, error) {
	collection := a.client.Database("goauth").Collection("audit_logs")

	var log models.AuditLog
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&log)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get audit log by id: %w", err)
	}
	return &log, nil
}

func (a *AuditLogRepository) DeleteAuditLog(ctx context.Context, log *models.AuditLog) error {
	collection := a.client.Database("goauth").Collection("audit_logs")

	_, err := collection.DeleteOne(ctx, bson.M{"_id": log.ID})
	if err != nil {
		return fmt.Errorf("failed to delete audit log: %w", err)
	}
	return nil
}
