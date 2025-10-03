package main

import (
	"context"
	"fmt"
	"log"

	// Import to auto-register gorm storage
	_ "github.com/bete7512/goauth/internal/storage/gorm"

	"github.com/bete7512/goauth/internal/modules/core/models"
	internalStorage "github.com/bete7512/goauth/internal/storage"
	"github.com/bete7512/goauth/pkg/storage"
)

// Example 1: Using supported GORM storage with PostgreSQL
func ExampleGormPostgres() {
	config := storage.StorageConfig{
		Driver:          "gorm",
		Dialect:         "postgres",
		DSN:             "host=localhost user=postgres password=secret dbname=authdb port=5432 sslmode=disable",
		AutoMigrate:     true,
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 300,
		LogLevel:        "info",
	}

	store, err := storage.NewStorage(config)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Get typed repository
	userRepo, err := storage.GetTypedRepository[models.UserRepository](
		store,
		internalStorage.CoreUserRepository,
	)
	if err != nil {
		log.Fatalf("Failed to get user repository: %v", err)
	}

	// Use repository
	user := &models.User{
		ID:       "user-123",
		Email:    "test@example.com",
		Password: "hashed_password",
		Name:     "Test User",
		Active:   true,
	}

	if err := userRepo.Create(ctx, user); err != nil {
		log.Printf("Error creating user: %v", err)
	} else {
		fmt.Println("User created successfully!")
	}

	// Find user
	foundUser, err := userRepo.FindByEmail(ctx, "test@example.com")
	if err != nil {
		log.Printf("Error finding user: %v", err)
	} else {
		fmt.Printf("Found user: %s (%s)\n", foundUser.Name, foundUser.Email)
	}
}

// Example 2: Using GORM with SQLite (for development/testing)
func ExampleGormSQLite() {
	config := storage.StorageConfig{
		Driver:      "gorm",
		Dialect:     "sqlite",
		DSN:         "./test.db",
		AutoMigrate: true,
		LogLevel:    "info",
	}

	store, err := storage.NewStorage(config)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	fmt.Println("SQLite storage initialized successfully!")
}

// Example 3: Using transactions
func ExampleTransaction() {
	config := storage.StorageConfig{
		Driver:      "gorm",
		Dialect:     "sqlite",
		DSN:         ":memory:",
		AutoMigrate: true,
	}

	store, err := storage.NewStorage(config)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Migrate models
	if err := store.Migrate(ctx, []interface{}{&models.User{}, &models.Session{}}); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	// Begin transaction
	tx, err := store.BeginTx(ctx)
	if err != nil {
		log.Fatalf("Failed to begin transaction: %v", err)
	}
	defer tx.Rollback() // Rollback if not committed

	// Get repositories within transaction
	userRepo, err := storage.GetTypedRepositoryFromTx[models.UserRepository](
		tx,
		internalStorage.CoreUserRepository,
	)
	if err != nil {
		log.Fatalf("Failed to get user repository: %v", err)
	}

	sessionRepo, err := storage.GetTypedRepositoryFromTx[models.SessionRepository](
		tx,
		internalStorage.CoreSessionRepository,
	)
	if err != nil {
		log.Fatalf("Failed to get session repository: %v", err)
	}

	// Create user
	user := &models.User{
		ID:       "user-456",
		Email:    "txuser@example.com",
		Password: "hashed_password",
		Name:     "Transaction User",
		Active:   true,
	}
	if err := userRepo.Create(ctx, user); err != nil {
		log.Fatalf("Failed to create user: %v", err)
	}

	// Create session for user
	session := &models.Session{
		ID:     "session-123",
		UserID: user.ID,
		Token:  "sample_token",
	}
	if err := sessionRepo.Create(ctx, session); err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		log.Fatalf("Failed to commit transaction: %v", err)
	}

	fmt.Println("Transaction completed successfully!")
}

// Example 4: Custom storage implementation
type CustomUserRepository struct {
	data map[string]*models.User
}

func NewCustomUserRepository() *CustomUserRepository {
	return &CustomUserRepository{
		data: make(map[string]*models.User),
	}
}

func (r *CustomUserRepository) Create(ctx context.Context, user *models.User) error {
	r.data[user.ID] = user
	return nil
}

func (r *CustomUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	for _, user := range r.data {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (r *CustomUserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	user, exists := r.data[id]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

func (r *CustomUserRepository) List(ctx context.Context, limit, offset int) ([]*models.User, error) {
	users := make([]*models.User, 0, len(r.data))
	for _, user := range r.data {
		users = append(users, user)
	}
	return users, nil
}

func (r *CustomUserRepository) Update(ctx context.Context, user *models.User) error {
	r.data[user.ID] = user
	return nil
}

func (r *CustomUserRepository) Delete(ctx context.Context, id string) error {
	delete(r.data, id)
	return nil
}

// Custom storage implementation
type CustomStorage struct {
	repositories map[string]interface{}
}

func NewCustomStorage() *CustomStorage {
	s := &CustomStorage{
		repositories: make(map[string]interface{}),
	}

	// Register custom repositories
	s.repositories[internalStorage.CoreUserRepository] = NewCustomUserRepository()
	// You would need to implement session repository as well...

	return s
}

func (s *CustomStorage) Initialize(ctx context.Context) error {
	return nil
}

func (s *CustomStorage) Close() error {
	return nil
}

func (s *CustomStorage) Migrate(ctx context.Context, models []interface{}) error {
	// Custom migration logic
	return nil
}

func (s *CustomStorage) BeginTx(ctx context.Context) (storage.Transaction, error) {
	// Implement transaction support
	return nil, fmt.Errorf("transactions not supported in this custom storage")
}

func (s *CustomStorage) DB() interface{} {
	return nil
}

func (s *CustomStorage) GetRepository(name string) interface{} {
	return s.repositories[name]
}

func (s *CustomStorage) RegisterRepository(name string, repo interface{}) {
	s.repositories[name] = repo
}

func ExampleCustomStorage() {
	customStore := NewCustomStorage()

	config := storage.StorageConfig{
		Driver:        "custom",
		CustomStorage: customStore,
	}

	store, err := storage.NewStorage(config)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Get repository
	userRepo, err := storage.GetTypedRepository[models.UserRepository](
		store,
		internalStorage.CoreUserRepository,
	)
	if err != nil {
		log.Fatalf("Failed to get user repository: %v", err)
	}

	// Use custom storage
	user := &models.User{
		ID:       "custom-user-1",
		Email:    "custom@example.com",
		Password: "password",
		Name:     "Custom User",
	}

	if err := userRepo.Create(ctx, user); err != nil {
		log.Printf("Error creating user: %v", err)
	} else {
		fmt.Println("User created in custom storage!")
	}

	foundUser, err := userRepo.FindByEmail(ctx, "custom@example.com")
	if err != nil {
		log.Printf("Error finding user: %v", err)
	} else {
		fmt.Printf("Found user in custom storage: %s\n", foundUser.Name)
	}
}

// Example 5: Partial custom repositories (override only specific repos)
func ExamplePartialCustomRepositories() {
	// Use custom implementation for user repository
	customUserRepo := NewCustomUserRepository()

	config := storage.StorageConfig{
		Driver:      "gorm",
		Dialect:     "sqlite",
		DSN:         ":memory:",
		AutoMigrate: true,
		// Override only the user repository
		CustomRepositories: map[string]interface{}{
			internalStorage.CoreUserRepository: customUserRepo,
		},
	}

	store, err := storage.NewStorage(config)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	fmt.Println("Storage with partial custom repositories initialized!")
	// Now user repository uses custom implementation,
	// but session repository uses GORM
}

func main() {
	fmt.Println("=== Storage Usage Examples ===\n")

	fmt.Println("Example 1: GORM with PostgreSQL")
	// ExampleGormPostgres() // Uncomment if you have PostgreSQL running

	fmt.Println("\nExample 2: GORM with SQLite")
	ExampleGormSQLite()

	fmt.Println("\nExample 3: Using Transactions")
	ExampleTransaction()

	fmt.Println("\nExample 4: Custom Storage")
	ExampleCustomStorage()

	fmt.Println("\nExample 5: Partial Custom Repositories")
	ExamplePartialCustomRepositories()

	fmt.Println("\n=== All examples completed ===")
}
