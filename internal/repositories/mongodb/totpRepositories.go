package mongodb

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type TotpSecretRepository struct {
	client *mongo.Client
}

func NewTotpSecretRepository(client *mongo.Client) interfaces.TotpSecretRepository {
	return &TotpSecretRepository{client: client}
}

func (t *TotpSecretRepository) GetTOTPSecretByUserID(ctx context.Context, userID string) (*models.TotpSecret, error) {
	collection := t.client.Database("goauth").Collection("totp_secrets")

	var secret models.TotpSecret
	err := collection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&secret)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get TOTP secret: %w", err)
	}
	return &secret, nil
}

func (t *TotpSecretRepository) CreateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	collection := t.client.Database("goauth").Collection("totp_secrets")

	_, err := collection.InsertOne(ctx, secret)
	if err != nil {
		return fmt.Errorf("failed to create TOTP secret: %w", err)
	}
	return nil
}

func (t *TotpSecretRepository) UpdateTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	collection := t.client.Database("goauth").Collection("totp_secrets")

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"user_id": secret.UserID},
		bson.M{"$set": secret},
	)
	if err != nil {
		return fmt.Errorf("failed to update TOTP secret: %w", err)
	}
	return nil
}

func (t *TotpSecretRepository) DeleteTOTPSecret(ctx context.Context, secret *models.TotpSecret) error {
	collection := t.client.Database("goauth").Collection("totp_secrets")

	_, err := collection.DeleteOne(ctx, bson.M{"user_id": secret.UserID})
	if err != nil {
		return fmt.Errorf("failed to delete TOTP secret: %w", err)
	}
	return nil
}
