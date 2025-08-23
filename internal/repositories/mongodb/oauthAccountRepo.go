package mongodb

import (
	"context"
	"fmt"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type OauthAccountRepository struct {
	client *mongo.Client
}

func NewOauthAccountRepository(client *mongo.Client) interfaces.OauthAccountRepository {
	return &OauthAccountRepository{client: client}
}

func (o *OauthAccountRepository) GetOauthAccountByUserID(ctx context.Context, userID string) (*models.OauthAccount, error) {
	collection := o.client.Database("goauth").Collection("oauth_accounts")

	var account models.OauthAccount
	err := collection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&account)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get OAuth account: %w", err)
	}
	return &account, nil
}

func (o *OauthAccountRepository) CreateOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	collection := o.client.Database("goauth").Collection("oauth_accounts")

	_, err := collection.InsertOne(ctx, account)
	if err != nil {
		return fmt.Errorf("failed to create OAuth account: %w", err)
	}
	return nil
}

func (o *OauthAccountRepository) UpdateOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	collection := o.client.Database("goauth").Collection("oauth_accounts")

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"user_id": account.UserID},
		bson.M{"$set": account},
	)
	if err != nil {
		return fmt.Errorf("failed to update OAuth account: %w", err)
	}
	return nil
}

func (o *OauthAccountRepository) DeleteOauthAccount(ctx context.Context, account *models.OauthAccount) error {
	collection := o.client.Database("goauth").Collection("oauth_accounts")

	_, err := collection.DeleteOne(ctx, bson.M{"user_id": account.UserID})
	if err != nil {
		return fmt.Errorf("failed to delete OAuth account: %w", err)
	}
	return nil
}
