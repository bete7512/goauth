package senders

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/bete7512/goauth/internal/modules/notification/models"
)

// SMTPEmailSender implements EmailSender using standard SMTP
type SMTPEmailSender struct {
	host            string
	port            int
	username        string
	password        string
	defaultFrom     string
	defaultFromName string
	useTLS          bool
}

// SMTPConfig holds SMTP configuration
type SMTPConfig struct {
	Host            string
	Port            int
	Username        string
	Password        string
	DefaultFrom     string
	DefaultFromName string
	UseTLS          bool
}

// NewSMTPEmailSender creates a new SMTP email sender
func NewSMTPEmailSender(config *SMTPConfig) *SMTPEmailSender {
	return &SMTPEmailSender{
		host:            config.Host,
		port:            config.Port,
		username:        config.Username,
		password:        config.Password,
		defaultFrom:     config.DefaultFrom,
		defaultFromName: config.DefaultFromName,
		useTLS:          config.UseTLS,
	}
}

// SendEmail sends an email using SMTP
func (s *SMTPEmailSender) SendEmail(ctx context.Context, message *models.EmailMessage) error {
	from := message.From
	if from == "" {
		from = s.defaultFrom
	}

	fromName := message.FromName
	if fromName == "" {
		fromName = s.defaultFromName
	}

	// Build email message
	var msg strings.Builder
	fmt.Fprintf(&msg, "From: %s <%s>\r\n", fromName, from)
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(message.To, ","))

	if len(message.CC) > 0 {
		fmt.Fprintf(&msg, "Cc: %s\r\n", strings.Join(message.CC, ","))
	}

	if message.ReplyTo != "" {
		fmt.Fprintf(&msg, "Reply-To: %s\r\n", message.ReplyTo)
	}

	fmt.Fprintf(&msg, "Subject: %s\r\n", message.Subject)
	msg.WriteString("MIME-Version: 1.0\r\n")

	// Add custom headers
	for key, value := range message.Headers {
		fmt.Fprintf(&msg, "%s: %s\r\n", key, value)
	}

	// Simple multipart if both text and HTML
	if message.TextBody != "" && message.HTMLBody != "" {
		boundary := "boundary123456"
		fmt.Fprintf(&msg, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary)

		fmt.Fprintf(&msg, "--%s\r\n", boundary)
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		msg.WriteString(message.TextBody)
		msg.WriteString("\r\n\r\n")

		fmt.Fprintf(&msg, "--%s\r\n", boundary)
		msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		msg.WriteString(message.HTMLBody)
		msg.WriteString("\r\n\r\n")

		fmt.Fprintf(&msg, "--%s--\r\n", boundary)
	} else if message.HTMLBody != "" {
		msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		msg.WriteString(message.HTMLBody)
	} else {
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		msg.WriteString(message.TextBody)
	}

	// Collect all recipients
	recipients := append([]string{}, message.To...)
	recipients = append(recipients, message.CC...)
	recipients = append(recipients, message.BCC...)

	// Connect and send
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	var auth smtp.Auth
	if s.username != "" && s.password != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	if s.useTLS {
		// Use TLS
		tlsConfig := &tls.Config{
			ServerName: s.host,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("smtp: failed to connect with TLS: %w", err)
		}
		defer func() { _ = conn.Close() }()

		client, err := smtp.NewClient(conn, s.host)
		if err != nil {
			return fmt.Errorf("smtp: failed to create client: %w", err)
		}
		defer func() { _ = client.Quit() }()

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("smtp: authentication failed: %w", err)
			}
		}

		if err := client.Mail(from); err != nil {
			return fmt.Errorf("smtp: failed to set sender: %w", err)
		}

		for _, recipient := range recipients {
			if err := client.Rcpt(recipient); err != nil {
				return fmt.Errorf("smtp: failed to add recipient: %w", err)
			}
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("smtp: failed to get data writer: %w", err)
		}

		if _, err := w.Write([]byte(msg.String())); err != nil {
			return fmt.Errorf("smtp: failed to write message: %w", err)
		}

		if err := w.Close(); err != nil {
			return fmt.Errorf("smtp: failed to close data writer: %w", err)
		}

		return nil
	}

	// Standard SMTP without TLS
	return smtp.SendMail(addr, auth, from, recipients, []byte(msg.String()))
}

// VerifyConfig verifies the SMTP connection
func (s *SMTPEmailSender) VerifyConfig(ctx context.Context) error {
	if s.host == "" {
		return fmt.Errorf("smtp: host is required")
	}
	if s.port == 0 {
		return fmt.Errorf("smtp: port is required")
	}
	return nil
}
