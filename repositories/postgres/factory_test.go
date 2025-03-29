package postgres

import (
	"testing"

	"github.com/bete7512/goauth/interfaces"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestNewRepositoryFactory(t *testing.T) {
	// Setup an in-memory SQLite database for testing
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Test creating a new repository factory
	factory := NewRepositoryFactory(db)

	// Verify the factory implements the interface
	if _, ok := factory.(interfaces.RepositoryFactory); !ok {
		t.Fatal("Factory does not implement interfaces.RepositoryFactory")
	}
}

func TestGetUserRepository(t *testing.T) {
	// Setup an in-memory SQLite database for testing
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Create a new repository factory
	factory := NewRepositoryFactory(db)

	// Get the user repository
	userRepo := factory.GetUserRepository()

	// Verify we got a non-nil repository
	if userRepo == nil {
		t.Fatal("Expected non-nil UserRepository")
	}

	// Verify the repository implements the interface
	if _, ok := userRepo.(interfaces.UserRepository); !ok {
		t.Fatal("Repository does not implement interfaces.UserRepository")
	}

	// Verify it's the correct concrete type
	_, ok := userRepo.(*UserRepository)
	if !ok {
		t.Fatal("Expected UserRepository to be of type *postgres.UserRepository")
	}
}

func TestGetTokenRepository(t *testing.T) {
	// Setup an in-memory SQLite database for testing
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Create a new repository factory
	factory := NewRepositoryFactory(db)

	// Get the token repository
	tokenRepo := factory.GetTokenRepository()

	// Verify we got a non-nil repository
	if tokenRepo == nil {
		t.Fatal("Expected non-nil TokenRepository")
	}

	// Verify the repository implements the interface
	if _, ok := tokenRepo.(interfaces.TokenRepository); !ok {
		t.Fatal("Repository does not implement interfaces.TokenRepository")
	}

	// Verify it's the correct concrete type
	_, ok := tokenRepo.(*TokenRepository)
	if !ok {
		t.Fatal("Expected TokenRepository to be of type *postgres.TokenRepository")
	}
}
