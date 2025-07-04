package mongodb

import (
	"context"
	"time"

	"github.com/bete7512/goauth/pkg/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type TokenRepository struct {
	client *mongo.Client
}

func NewTokenRepository(client *mongo.Client) *TokenRepository {
	return &TokenRepository{client: client}
}

// SaveToken saves a token of any type
func (t *TokenRepository) SaveToken(ctx context.Context, userID, token string, tokenType models.TokenType, expiry time.Duration) error {
	collection := t.client.Database("goauth").Collection("tokens")

	now := time.Now()
	used := false
	newToken := models.Token{
		UserID:     userID,
		TokenType:  tokenType,
		TokenValue: token,
		ExpiresAt:  now.Add(expiry),
		Used:       &used,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	_, err := collection.InsertOne(ctx, newToken)
	if err != nil {
		return err
	}
	return nil
}

// SaveTokenWithDeviceId saves a token with device ID
func (t *TokenRepository) SaveTokenWithDeviceId(ctx context.Context, userID, token, deviceId string, tokenType models.TokenType, expiry time.Duration) error {
	// For MongoDB, we'll store device ID in the ActionType field as a workaround
	// since the Token model doesn't have a DeviceID field
	collection := t.client.Database("goauth").Collection("tokens")

	now := time.Now()
	used := false
	newToken := models.Token{
		UserID:     userID,
		TokenType:  tokenType,
		TokenValue: token,
		ActionType: deviceId, // Store device ID in ActionType field
		ExpiresAt:  now.Add(expiry),
		Used:       &used,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	_, err := collection.InsertOne(ctx, newToken)
	if err != nil {
		return err
	}
	return nil
}

// GetActiveTokenByUserIdAndType implements interfaces.TokenRepository.
func (t *TokenRepository) GetActiveTokenByUserIdAndType(ctx context.Context, userID string, tokenType models.TokenType) (*models.Token, error) {
	collection := t.client.Database("goauth").Collection("tokens")

	var token models.Token
	err := collection.FindOne(ctx, bson.M{
		"user_id":    userID,
		"token_type": tokenType,
		"used":       false,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&token)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

// GetActiveTokenByUserIdTypeAndDeviceId implements interfaces.TokenRepository.
func (t *TokenRepository) GetActiveTokenByUserIdTypeAndDeviceId(ctx context.Context, userID string, tokenType models.TokenType, deviceID string) (*models.Token, error) {
	collection := t.client.Database("goauth").Collection("tokens")

	var token models.Token
	err := collection.FindOne(ctx, bson.M{
		"user_id":     userID,
		"token_type":  tokenType,
		"action_type": deviceID, // Device ID is stored in ActionType field
		"used":        false,
		"expires_at":  bson.M{"$gt": time.Now()},
	}).Decode(&token)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &token, nil
}

// RevokeToken implements interfaces.TokenRepository.
func (t *TokenRepository) RevokeToken(ctx context.Context, tokenId string) error {
	collection := t.client.Database("goauth").Collection("tokens")

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"_id": tokenId},
		bson.M{"$set": bson.M{"used": true}},
	)
	return err
}

// RevokeAllTokens implements interfaces.TokenRepository.
func (t *TokenRepository) RevokeAllTokens(ctx context.Context, userID string, tokenType models.TokenType) error {
	collection := t.client.Database("goauth").Collection("tokens")

	_, err := collection.UpdateMany(
		ctx,
		bson.M{"user_id": userID, "token_type": tokenType},
		bson.M{"$set": bson.M{"used": true}},
	)
	return err
}

// CleanExpiredTokens implements interfaces.TokenRepository.
func (t *TokenRepository) CleanExpiredTokens(ctx context.Context, tokenType models.TokenType) error {
	collection := t.client.Database("goauth").Collection("tokens")

	_, err := collection.UpdateMany(
		ctx,
		bson.M{"token_type": tokenType, "expires_at": bson.M{"$lt": time.Now()}},
		bson.M{"$set": bson.M{"used": true}},
	)
	return err
}
