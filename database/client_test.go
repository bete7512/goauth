package database

import (
	"testing"

	"github.com/bete7512/goauth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

// MockDBClient is a mock implementation of DBClient interface
type MockDBClient struct {
	mock.Mock
}

func (m *MockDBClient) Connect() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDBClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDBClient) GetDB() *gorm.DB {
	args := m.Called()
	return args.Get(0).(*gorm.DB)
}

func TestNewDBClient(t *testing.T) {
	tests := []struct {
		name        string
		config      types.DatabaseConfig
		wantErr     bool
		errContains string
	}{
		{
			name: "valid postgres config",
			config: types.DatabaseConfig{
				Type:        types.PostgreSQL,
				URL:         "postgres://user@localhost:5432/dbname",
				AutoMigrate: true,
			},
			wantErr: false,
		},
		{
			name: "unsupported database type",
			config: types.DatabaseConfig{
				Type: "unsupported",
				URL:  "invalid",
			},
			wantErr:     true,
			errContains: "unsupported database type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewDBClient(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.IsType(t, &PostgresClient{}, client)
			}
		})
	}
}

func TestPostgresClient_Connect(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantErr     bool
		errContains string
	}{
		{
			name:        "invalid connection string",
			url:         "invalid",
			wantErr:     true,
			errContains: "failed to connect to PostgreSQL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &PostgresClient{
				URL:         tt.url,
				AutoMigrate: true,
			}

			err := client.Connect()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client.DB)
			}
		})
	}
}

func TestPostgresClient_Close(t *testing.T) {
	t.Run("close with nil DB", func(t *testing.T) {
		client := &PostgresClient{}
		err := client.Close()
		assert.NoError(t, err)
	})
}

func TestPostgresClient_GetDB(t *testing.T) {
	t.Run("get DB", func(t *testing.T) {
		mockDB := &gorm.DB{}
		client := &PostgresClient{
			DB: mockDB,
		}
		assert.Equal(t, mockDB, client.GetDB())
	})
}

// Example usage of MockDBClient
func TestMockDBClientUsage(t *testing.T) {
	mockClient := new(MockDBClient)
	mockDB := &gorm.DB{}

	// Set up expectations
	mockClient.On("Connect").Return(nil)
	mockClient.On("GetDB").Return(mockDB)
	mockClient.On("Close").Return(nil)

	// Test the mock
	err := mockClient.Connect()
	assert.NoError(t, err)

	db := mockClient.GetDB()
	assert.Equal(t, mockDB, db)

	err = mockClient.Close()
	assert.NoError(t, err)

	// Verify that all expectations were met
	mockClient.AssertExpectations(t)
}
