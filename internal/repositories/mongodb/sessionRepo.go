package mongodb

import (
	"context"

	"github.com/bete7512/goauth/pkg/interfaces"
	"github.com/bete7512/goauth/pkg/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type SessionRepository struct {
	client *mongo.Client
}

func NewSessionRepository(client *mongo.Client) interfaces.SessionRepository {
	return &SessionRepository{client: client}
}

func (s *SessionRepository) GetSessionByUserID(ctx context.Context, userID string) ([]models.Session, error) {
	collection := s.client.Database("goauth").Collection("sessions")

	var sessions []models.Session
	cursor, err := collection.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if err = cursor.All(ctx, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (s *SessionRepository) GetSessionBySessionID(ctx context.Context, sessionID string) (*models.Session, error) {
	collection := s.client.Database("goauth").Collection("sessions")

	var session models.Session
	err := collection.FindOne(ctx, bson.M{"_id": sessionID}).Decode(&session)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *SessionRepository) CreateSession(ctx context.Context, session *models.Session) error {
	collection := s.client.Database("goauth").Collection("sessions")

	_, err := collection.InsertOne(ctx, session)
	return err
}

func (s *SessionRepository) UpdateSession(ctx context.Context, session *models.Session) error {
	collection := s.client.Database("goauth").Collection("sessions")

	_, err := collection.ReplaceOne(
		ctx,
		bson.M{"_id": session.ID},
		session,
	)
	return err
}

func (s *SessionRepository) DeleteSession(ctx context.Context, session *models.Session) error {
	collection := s.client.Database("goauth").Collection("sessions")

	_, err := collection.DeleteOne(ctx, bson.M{"_id": session.ID})
	return err
}

func (s *SessionRepository) DeleteAllUserSessions(ctx context.Context, userID string) error {
	collection := s.client.Database("goauth").Collection("sessions")

	_, err := collection.DeleteMany(ctx, bson.M{"user_id": userID})
	return err
}
