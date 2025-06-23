package config

type SendGridConfig struct {
	APIKey string
}

type SESConfig struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
}
