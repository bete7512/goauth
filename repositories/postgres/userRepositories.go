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

	// Use FindOne instead of First to avoid the automatic error logging
	err := u.db.Where("email = ?", email).Take(&user).Error
	// Handle record not found
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// gorm always display error even if I hhandled error record not found and displays err with red line in my terminal
func (u *UserRepository) GetUserByID(id string) (*models.User, error) {
	var user models.User
	if err := u.db.Where("id = ?", id).First(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}
	return &user, nil
}

func (u *UserRepository) UpdateUser(user *models.User) error {
	if err := u.db.Debug().Model(&models.User{}).Where("id = ?", user.ID).Updates(user).Error; err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

func (u *UserRepository) UpsertUserByEmail(user *models.User) error {
	existingUser := models.User{}
	if err := u.db.Where("email = ?", user.Email).First(&existingUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			user.ID = uuid.New().String()
			if err := u.db.Create(user).Error; err != nil {
				return fmt.Errorf("failed to upsert user: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get user by email: %w", err)
		}
	} else {
		if err := u.db.Model(&models.User{}).Where("id = ?", existingUser.ID).Updates(user).Error; err != nil {
			return fmt.Errorf("failed to update user: %w", err)
		}
	}
	return nil
}

func (u *UserRepository) DeleteUser(user *models.User) error {
	if err := u.db.Delete(user).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

func (u *UserRepository) GetAllUsers(filter interfaces.Filter) ([]*models.User, int64, error) {
	var users []*models.User
	var total int64
	var err error
	if filter.Search != "" {
		err = u.db.Where("email LIKE ?", "%"+filter.Search+"%").Or("first_name ILIKE ?", "%"+filter.Search+"%").Or("last_name ILIKE ?", "%"+filter.Search+"%").Find(&users).Error
	} else {
		err = u.db.Find(&users).Error
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get all users: %w", err)
	}
	if err := u.db.Model(&models.User{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}
	if filter.Page > 0 && filter.Limit > 0 {
		offset := (filter.Page - 1) * filter.Limit
		if err := u.db.Offset(offset).Limit(filter.Limit).Find(&users).Error; err != nil {
			return nil, 0, fmt.Errorf("failed to paginate users: %w", err)
		}
	}
	if filter.Sort.Field != "" {
		if filter.Sort.Direction == "asc" {
			err = u.db.Order(fmt.Sprintf("%s ASC", filter.Sort.Field)).Find(&users).Error
		} else {
			err = u.db.Order(fmt.Sprintf("%s DESC", filter.Sort.Field)).Find(&users).Error
		}
		if err != nil {
			return nil, 0, fmt.Errorf("failed to sort users: %w", err)
		}
	}
	return users, total, nil
}
