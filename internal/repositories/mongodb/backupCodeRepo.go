package mongodb

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type BackupCodeRepository struct {
	client *mongo.Client
}

func NewBackupCodeRepository(client *mongo.Client) interfaces.BackupCodeRepository {
	return &BackupCodeRepository{client: client}
}

func (b *BackupCodeRepository) GetBackupCodeByUserID(ctx context.Context, userID string) (*models.BackupCode, error) {
	collection := b.client.Database("goauth").Collection("backup_codes")

	var code models.BackupCode
	err := collection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&code)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get backup code: %w", err)
	}
	return &code, nil
}

func (b *BackupCodeRepository) CreateBackupCodes(ctx context.Context, codes []*models.BackupCode) error {
	collection := b.client.Database("goauth").Collection("backup_codes")

	// Convert slice of pointers to slice of values for MongoDB
	var documents []interface{}
	for _, code := range codes {
		documents = append(documents, code)
	}

	_, err := collection.InsertMany(ctx, documents)
	if err != nil {
		return fmt.Errorf("failed to create backup codes: %w", err)
	}
	return nil
}

func (b *BackupCodeRepository) UpdateBackupCode(ctx context.Context, code *models.BackupCode) error {
	collection := b.client.Database("goauth").Collection("backup_codes")

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"user_id": code.UserID},
		bson.M{"$set": code},
	)
	if err != nil {
		return fmt.Errorf("failed to update backup code: %w", err)
	}
	return nil
}

func (b *BackupCodeRepository) DeleteBackupCode(ctx context.Context, code *models.BackupCode) error {
	collection := b.client.Database("goauth").Collection("backup_codes")

	_, err := collection.DeleteOne(ctx, bson.M{"user_id": code.UserID})
	if err != nil {
		return fmt.Errorf("failed to delete backup code: %w", err)
	}
	return nil
}
