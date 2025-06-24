package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func BenchmarkRegisterHandler(b *testing.B) {
	payload := map[string]interface{}{
		"email":    "test@example.com",
		"password": "password123",
	}

	jsonData, _ := json.Marshal(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// TODO: Add actual handler benchmark
		_ = req
		_ = w
	}
}

func BenchmarkLoginHandler(b *testing.B) {
	payload := map[string]interface{}{
		"email":    "test@example.com",
		"password": "password123",
	}

	jsonData, _ := json.Marshal(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// TODO: Add actual handler benchmark
		_ = req
		_ = w
	}
}
