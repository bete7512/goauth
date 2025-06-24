package utils

import (
	"net/url"
	"strings"
)

// GetBaseURL returns the scheme + host part of the URL
func GetBaseURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "" // or handle the error as needed
	}
	return parsed.Scheme + "://" + parsed.Host
}

// GetEndpoint returns the path part of the URL
func GetEndpoint(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "" // or handle the error as needed
	}
	// Ensure it starts with "/"
	if !strings.HasPrefix(parsed.Path, "/") {
		return "/" + parsed.Path
	}
	return parsed.Path
}
