//go:build integration

package testhelpers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// JSONPost sends a POST request with a JSON body.
func JSONPost(handler http.Handler, path string, body map[string]interface{}, headers ...map[string]string) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	applyHeaders(req, headers)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// JSONPut sends a PUT request with a JSON body.
func JSONPut(handler http.Handler, path string, body map[string]interface{}, headers ...map[string]string) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	applyHeaders(req, headers)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// JSONGet sends a GET request.
func JSONGet(handler http.Handler, path string, headers ...map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	applyHeaders(req, headers)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// JSONDelete sends a DELETE request.
func JSONDelete(handler http.Handler, path string, headers ...map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("DELETE", path, nil)
	applyHeaders(req, headers)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// ParseJSON decodes a JSON response body into a map.
func ParseJSON(t *testing.T, body io.Reader) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	err := json.NewDecoder(body).Decode(&result)
	require.NoError(t, err)
	return result
}

// AuthHeader returns an Authorization: Bearer header map.
func AuthHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func applyHeaders(req *http.Request, headers []map[string]string) {
	for _, h := range headers {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
}
