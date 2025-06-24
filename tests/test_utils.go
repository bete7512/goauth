package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/bete7512/goauth/pkg/auth"
	"github.com/bete7512/goauth/pkg/config"
)

// TestUtils provides common utilities for testing
type TestUtils struct {
	AuthService *auth.AuthService
	Config      config.Config
}

// NewTestUtils creates a new test utilities instance
func NewTestUtils() (*TestUtils, error) {
	config := GetTestConfig()
	authService, err := auth.NewBuilder().WithConfig(config).Build()
	if err != nil {
		return nil, err
	}

	return &TestUtils{
		AuthService: authService,
		Config:      config,
	}, nil
}

// CreateTestRequest creates a test HTTP request
func (tu *TestUtils) CreateTestRequest(method, path string, body interface{}) *http.Request {
	var req *http.Request

	if body != nil {
		jsonData, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}

	return req
}

// CreateTestResponse creates a test HTTP response recorder
func (tu *TestUtils) CreateTestResponse() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

// GetTestUserData returns test user data
func GetTestUserData() map[string]interface{} {
	return map[string]interface{}{
		"email":    "test@example.com",
		"password": "Password123!",
		"name":     "Test User",
	}
}

// GetTestLoginData returns test login data
func GetTestLoginData() map[string]interface{} {
	return map[string]interface{}{
		"email":    "test@example.com",
		"password": "Password123!",
	}
}
