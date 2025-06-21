package external

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bete7512/goauth/logger"
)

// Logger interface — replace with your actual logger

// APIClient handles external HTTP API calls
type APIClient struct {
	httpClient *http.Client
	baseURL    string
	logger     logger.Log
}

// NewAPIClient initializes a new API client
func NewAPIClient(baseURL string, logger logger.Log) *APIClient {
	return &APIClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    baseURL,
		logger:     logger,
	}
}

// Get makes a GET request and decodes JSON response into result
func (c *APIClient) Get(ctx context.Context, endpoint string, result interface{}) error {
	url := c.baseURL + endpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		c.logger.Errorf("Failed to create GET request: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Errorf("Failed to perform GET request to %s: %v", url, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		c.logger.Errorf("GET request to %s failed with status: %d", url, resp.StatusCode)
		return fmt.Errorf("GET request failed with status: %d", resp.StatusCode)
	}

	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}

	return nil
}

// Post makes a POST request with a JSON payload and decodes JSON response
func (c *APIClient) Post(ctx context.Context, endpoint string, payload, result interface{}) error {
	url := c.baseURL + endpoint

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		c.logger.Errorf("Failed to encode POST payload: %v", err)
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		c.logger.Errorf("Failed to create POST request: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Errorf("Failed to perform POST request to %s: %v", url, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		c.logger.Errorf("POST request to %s failed with status: %d", url, resp.StatusCode)
		return fmt.Errorf("POST request failed with status: %d", resp.StatusCode)
	}

	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}

	return nil
}

// CreateFormRequest creates a request with form data
func (c *APIClient) CreateFormRequest(ctx context.Context, method, endpoint string, data url.Values) (*http.Request, error) {
	url := c.baseURL + endpoint

	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(data.Encode()))
	if err != nil {
		c.logger.Errorf("Failed to create form request: %v", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// DoRequest executes a request and returns the response
func (c *APIClient) DoRequest(req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Errorf("Failed to perform request: %v", err)
		return nil, err
	}

	return resp, nil
}
