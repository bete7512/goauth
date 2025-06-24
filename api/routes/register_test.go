package routes

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bete7512/goauth/models"
	"github.com/bete7512/goauth/schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

func TestHandleRegister_Success(t *testing.T) {
	conf := CreateTestConfig()
	handler := CreateTestAuthHandler(conf)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)
	mockTokenRepo := handler.Auth.Repository.GetTokenRepository().(*MockTokenRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Mock user not exists
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return((*models.User)(nil), gorm.ErrRecordNotFound)

	// Mock password hashing
	mockTokenManager.On("HashPassword", "password123").Return("hashed_password", nil)

	// Mock user creation
	mockUserRepo.On("CreateUser", mock.AnythingOfType("*models.User")).Return(nil)

	// Mock token generation
	mockTokenManager.On("GenerateTokens", mock.AnythingOfType("*models.User")).Return("access_token", "refresh_token", nil)

	// Mock token saving
	mockTokenRepo.On("SaveToken", mock.AnythingOfType("string"), "refresh_token", models.RefreshToken, time.Duration(86400)).Return(nil)

	// Create request
	reqBody := schemas.RegisterRequest{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "test@example.com",
		Password:  "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRegister(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", response["email"])
	assert.Equal(t, "John", response["first_name"])
	assert.Equal(t, "Doe", response["last_name"])

	// Verify mocks
	mockUserRepo.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
}

func TestHandleRegister_EmailAlreadyExists(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Mock existing user
	existingUser := &models.User{Email: "test@example.com"}
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return(existingUser, nil)

	// Create request
	reqBody := schemas.RegisterRequest{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "test@example.com",
		Password:  "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRegister(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Email already exists", response["error"])

	mockUserRepo.AssertExpectations(t)
}

func TestHandleRegister_DatabaseError(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)

	// Mock database error
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return((*models.User)(nil), errors.New("database connection failed"))

	// Create request
	reqBody := schemas.RegisterRequest{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "test@example.com",
		Password:  "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRegister(w, req)

	// Assertions
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "Failed to check if email exists")

	mockUserRepo.AssertExpectations(t)
}

func TestHandleRegister_PasswordHashingError(t *testing.T) {
	config := CreateTestConfig()
	handler := CreateTestAuthHandler(config)

	// Setup mocks
	mockUserRepo := handler.Auth.Repository.GetUserRepository().(*MockUserRepository)
	mockTokenManager := handler.Auth.TokenManager.(*MockTokenManager)

	// Mock user not exists
	mockUserRepo.On("GetUserByEmail", "test@example.com").Return((*models.User)(nil), gorm.ErrRecordNotFound)

	// Mock password hashing error
	mockTokenManager.On("HashPassword", "password123").Return("", errors.New("hashing failed"))

	// Create request
	reqBody := schemas.RegisterRequest{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "test@example.com",
		Password:  "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	handler.HandleRegister(w, req)

	// Assertions
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "Failed to secure password")

	mockUserRepo.AssertExpectations(t)
	mockTokenManager.AssertExpectations(t)
}
