package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserRepository struct {
	client *mongo.Client
}

func NewUserRepository(client *mongo.Client) interfaces.UserRepository {
	return &UserRepository{client: client}
}

func (u *UserRepository) GetAllUsers(ctx context.Context, filter interfaces.Filter) ([]*models.User, int64, error) {
	collection := u.client.Database("goauth").Collection("users")

	// Build filter
	filterBson := bson.M{}
	if filter.Search != "" {
		filterBson = bson.M{
			"$or": []bson.M{
				{"email": bson.M{"$regex": filter.Search, "$options": "i"}},
				{"first_name": bson.M{"$regex": filter.Search, "$options": "i"}},
				{"last_name": bson.M{"$regex": filter.Search, "$options": "i"}},
			},
		}
	}

	// Count total
	total, err := collection.CountDocuments(ctx, filterBson)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
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

	// Find users
	cursor, err := collection.Find(ctx, filterBson, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get users: %w", err)
	}
	defer cursor.Close(ctx)

	var users []*models.User
	if err = cursor.All(ctx, &users); err != nil {
		return nil, 0, fmt.Errorf("failed to decode users: %w", err)
	}

	return users, total, nil
}

func (u *UserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	collection := u.client.Database("goauth").Collection("users")

	var user models.User
	err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return &user, nil
}

func (u *UserRepository) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	collection := u.client.Database("goauth").Collection("users")

	var user models.User
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}
	return &user, nil
}

func (u *UserRepository) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*models.User, error) {
	collection := u.client.Database("goauth").Collection("users")

	var user models.User
	err := collection.FindOne(ctx, bson.M{"phone_number": phoneNumber}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to get user by phone number: %w", err)
	}
	return &user, nil
}

func (u *UserRepository) CreateUser(ctx context.Context, user *models.User) error {
	collection := u.client.Database("goauth").Collection("users")

	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	_, err := collection.InsertOne(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (u *UserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	collection := u.client.Database("goauth").Collection("users")

	user.UpdatedAt = time.Now()

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"_id": user.ID},
		bson.M{"$set": user},
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

func (u *UserRepository) UpsertUserByEmail(ctx context.Context, user *models.User) error {
	collection := u.client.Database("goauth").Collection("users")

	user.UpdatedAt = time.Now()

	opts := options.Update().SetUpsert(true)
	_, err := collection.UpdateOne(
		ctx,
		bson.M{"email": user.Email},
		bson.M{"$set": user},
		opts,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert user: %w", err)
	}
	return nil
}

func (u *UserRepository) DeleteUser(ctx context.Context, user *models.User) error {
	collection := u.client.Database("goauth").Collection("users")

	_, err := collection.DeleteOne(ctx, bson.M{"_id": user.ID})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}
