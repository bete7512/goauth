package postgres

import (
	"errors"
	"fmt"

	"github.com/bete7512/goauth/interfaces"
	"github.com/bete7512/goauth/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) interfaces.UserRepository {
	return &UserRepository{db: db}
}

func (u *UserRepository) CreateUser(user *models.User) error {
	user.ID = uuid.New().String()
	if err := u.db.Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (u *UserRepository) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	result := u.db.Where("email = ?", email).First(&user)
	
	if result.Error != nil {
		// Check specifically for record not found error
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		
		return nil, fmt.Errorf("failed to get user by email: %w", result.Error)
	}
	
	return &user, nil
}

func (u *UserRepository) GetUserByID(id string) (*models.User, error) {
	var user models.User
	if err := u.db.Where("id = ?", id).First(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}
	return &user, nil
}

func (u *UserRepository) UpdateUser(user *models.User) error {
	if err := u.db.Save(user).Error; err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

func (u *UserRepository) UpsertUserByEmail(user *models.User) error {
	if err := u.db.Where("email = ?", user.Email).Assign(user).FirstOrCreate(user).Error; err != nil {
		return fmt.Errorf("failed to upsert user: %w", err)
	}
	return nil
}

func (u *UserRepository) DeleteUser(user *models.User) error {
	if err := u.db.Delete(user).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}
