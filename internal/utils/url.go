package utils

import (
	"fmt"
	"net/url"
)

func ValidateUrl(u string) error {
	if u == "" {
		return fmt.Errorf("url is required")
	}

	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid url: %v", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("url must start with http or https")
	}

	if parsed.Host == "" {
		return fmt.Errorf("url must have a host")
	}

	return nil
}
