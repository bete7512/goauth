package utils

import "net/http"

func GetIpFromRequest(req *http.Request) string {
	// Check for X-Forwarded-For header first
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	// Fallback to RemoteAddr
	return req.RemoteAddr
}
