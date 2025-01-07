package interfaces


import "github.com/bete7512/go-auth/auth/models"

type UserRepository interface {
    CreateUser(user *models.User) error
    GetUserByEmail(email string) (*models.User, error)
    GetUserByID(id uint) (*models.User, error)
    UpdateUser(user *models.User) error
    DeleteUser(user *models.User) error
}

type RepositoryFactory interface {
    GetUserRepository() UserRepository
}