package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/bete7512/goauth/config"
	"github.com/bete7512/goauth/models"
)

type EmailSender struct {
	config     config.EmailConfig
	templates  *template.Template
	httpClient *http.Client
	sesClient  *ses.Client
}

type EmailTemplateData struct {
	LogoURL      string
	CompanyName  string
	PrimaryColor string
	UserName     string
	UserEmail    string
	ActionURL    string
	Token        string
	ExpiresAt    string
	SupportEmail string
	Year         int
}

func NewEmailSender(conf config.Config) *EmailSender {

	var tmpl *template.Template
	tmpl, err := template.ParseGlob("../notifications/templates/*.html")
	if err != nil {
		log.Println("Error parsing templates:", err)
	}

	var sesClient *ses.Client
	if conf.Email.Sender.Type == config.SES {
		if conf.Email.SES.AccessKeyID == "" || conf.Email.SES.SecretAccessKey == "" {
			log.Println("SES credentials not provided, falling back to SendGrid")
		} else {
			cfg, err := awsConfig.LoadDefaultConfig(context.TODO(),
				awsConfig.WithRegion(conf.Email.SES.Region),
				awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
					conf.Email.SES.AccessKeyID,
					conf.Email.SES.SecretAccessKey,
					"",
				)),
			)
			if err != nil {
				log.Printf("Error loading AWS config: %v", err)
			} else {
				sesClient = ses.NewFromConfig(cfg)
				log.Println("SES client initialized successfully")
			}
		}
	}

	return &EmailSender{
		config:    conf.Email,
		templates: tmpl,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		sesClient: sesClient,
	}
}

func (e *EmailSender) SendVerification(user models.User, redirectURL string) error {
	data := EmailTemplateData{
		LogoURL:      e.config.Branding.LogoURL,
		CompanyName:  e.config.Branding.CompanyName,
		PrimaryColor: e.config.Branding.PrimaryColor,
		UserName:     user.FirstName,
		UserEmail:    user.Email,
		ActionURL:    redirectURL,
		SupportEmail: e.config.Sender.SupportEmail,
		Year:         time.Now().Year(),
	}

	return e.sendEmail(user.Email, "Verify Your Email", "verify_email", data)
}

func (e *EmailSender) SendWelcome(user models.User) error {
	data := EmailTemplateData{
		LogoURL:      e.config.Branding.LogoURL,
		CompanyName:  e.config.Branding.CompanyName,
		PrimaryColor: e.config.Branding.PrimaryColor,
		UserName:     user.FirstName,
		UserEmail:    user.Email,
		SupportEmail: e.config.Sender.SupportEmail,
		Year:         time.Now().Year(),
	}

	return e.sendEmail(user.Email, "Welcome to "+e.config.Branding.CompanyName, "welcome", data)
}

func (e *EmailSender) SendPasswordReset(user models.User, redirectURL string) error {
	data := EmailTemplateData{
		LogoURL:      e.config.Branding.LogoURL,
		CompanyName:  e.config.Branding.CompanyName,
		PrimaryColor: e.config.Branding.PrimaryColor,
		UserName:     user.FirstName,
		UserEmail:    user.Email,
		ActionURL:    redirectURL,
		SupportEmail: e.config.Sender.SupportEmail,
		Year:         time.Now().Year(),
	}

	return e.sendEmail(user.Email, "Reset Your Password", "reset_password", data)
}

func (e *EmailSender) SendTwoFactorCode(user models.User, code string) error {
	data := EmailTemplateData{
		LogoURL:      e.config.Branding.LogoURL,
		CompanyName:  e.config.Branding.CompanyName,
		PrimaryColor: e.config.Branding.PrimaryColor,
		UserName:     user.FirstName,
		UserEmail:    user.Email,
		Token:        code,
		SupportEmail: e.config.Sender.SupportEmail,
		Year:         time.Now().Year(),
	}

	return e.sendEmail(user.Email, "Your Two-Factor Code", "two_factor", data)
}

func (e *EmailSender) SendMagicLink(user models.User, redirectURL string) error {
	data := EmailTemplateData{
		LogoURL:      e.config.Branding.LogoURL,
		CompanyName:  e.config.Branding.CompanyName,
		PrimaryColor: e.config.Branding.PrimaryColor,
		UserName:     user.FirstName,
		UserEmail:    user.Email,
		ActionURL:    redirectURL,
		SupportEmail: e.config.Sender.SupportEmail,
		Year:         time.Now().Year(),
	}

	return e.sendEmail(user.Email, "Your Magic Link", "magic_link", data)
}

func (e *EmailSender) sendEmail(to, subject, templateName string, data EmailTemplateData) error {
	// Use Amazon SES if configured, otherwise use SendGrid as default
	if e.config.Sender.Type == config.SES {
		if e.sesClient != nil {
			return e.sendViaSES(to, subject, templateName, data)
		} else {
			log.Println("SES client not available, falling back to SendGrid")
		}
	} else if e.config.Sender.Type == config.SendGrid && e.config.SendGrid.APIKey != "" {
		return e.sendViaSendGrid(to, subject, templateName, data)
	} else {
		return fmt.Errorf("neither SES nor SendGrid is properly configured")
	}
	return nil
}

func (e *EmailSender) sendViaSendGrid(to, subject, templateName string, data EmailTemplateData) error {
	// Render template
	var body bytes.Buffer
	err := e.templates.ExecuteTemplate(&body, templateName+".html", data)
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	// SendGrid API request
	payload := map[string]interface{}{
		"personalizations": []map[string]interface{}{
			{
				"to": []map[string]string{
					{"email": to},
				},
			},
		},
		"from": map[string]string{
			"email": e.config.Sender.FromEmail,
			"name":  e.config.Sender.FromName,
		},
		"subject": subject,
		"content": []map[string]string{
			{
				"type":  "text/html",
				"value": body.String(),
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+e.config.SendGrid.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("sendgrid API error: %d", resp.StatusCode)
	}

	return nil
}

func (e *EmailSender) sendViaSES(to, subject, templateName string, data EmailTemplateData) error {
	if e.sesClient == nil {
		return fmt.Errorf("SES client not initialized")
	}

	// Render template
	var body bytes.Buffer
	err := e.templates.ExecuteTemplate(&body, templateName+".html", data)
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	// Create SES input
	input := &ses.SendEmailInput{
		Source: aws.String(e.config.Sender.FromEmail),
		Destination: &types.Destination{
			ToAddresses: []string{to},
		},
		Message: &types.Message{
			Subject: &types.Content{
				Data:    aws.String(subject),
				Charset: aws.String("UTF-8"),
			},
			Body: &types.Body{
				Html: &types.Content{
					Data:    aws.String(body.String()),
					Charset: aws.String("UTF-8"),
				},
			},
		},
	}

	// Send email via SES
	_, err = e.sesClient.SendEmail(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to send email via SES: %w", err)
	}

	return nil
}
