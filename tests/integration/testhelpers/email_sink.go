//go:build integration

package testhelpers

import (
	"context"
	"regexp"
	"sync"

	notifmodels "github.com/bete7512/goauth/internal/modules/notification/models"
)

// EmailSink captures all emails sent during a test. Thread-safe.
// Use it as the EmailSender in notification module config to intercept
// verification emails, password reset links, magic link codes, etc.
type EmailSink struct {
	mu     sync.Mutex
	Emails []notifmodels.EmailMessage
}

var _ notifmodels.EmailSender = (*EmailSink)(nil)

func NewEmailSink() *EmailSink {
	return &EmailSink{}
}

func (s *EmailSink) SendEmail(_ context.Context, msg *notifmodels.EmailMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Emails = append(s.Emails, *msg)
	return nil
}

func (s *EmailSink) VerifyConfig(_ context.Context) error {
	return nil
}

// LastEmail returns the most recently sent email, or nil if none.
func (s *EmailSink) LastEmail() *notifmodels.EmailMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Emails) == 0 {
		return nil
	}
	e := s.Emails[len(s.Emails)-1]
	return &e
}

// Count returns the number of emails captured.
func (s *EmailSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Emails)
}

// ExtractCode searches the last email body for a 6-digit numeric code.
func (s *EmailSink) ExtractCode() string {
	email := s.LastEmail()
	if email == nil {
		return ""
	}
	re := regexp.MustCompile(`\b(\d{6})\b`)
	if m := re.FindStringSubmatch(email.TextBody); len(m) > 1 {
		return m[1]
	}
	if m := re.FindStringSubmatch(email.HTMLBody); len(m) > 1 {
		return m[1]
	}
	return ""
}

// ExtractLink searches the last email body for a URL containing the given substring.
func (s *EmailSink) ExtractLink(contains string) string {
	email := s.LastEmail()
	if email == nil {
		return ""
	}
	re := regexp.MustCompile(`https?://[^\s"<>]+` + regexp.QuoteMeta(contains) + `[^\s"<>]*`)
	if m := re.FindString(email.TextBody); m != "" {
		return m
	}
	if m := re.FindString(email.HTMLBody); m != "" {
		return m
	}
	return ""
}

// ExtractToken searches the last email body for a token= query parameter value.
func (s *EmailSink) ExtractToken() string {
	email := s.LastEmail()
	if email == nil {
		return ""
	}
	re := regexp.MustCompile(`token=([a-zA-Z0-9_\-]+)`)
	for _, body := range []string{email.TextBody, email.HTMLBody} {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}
