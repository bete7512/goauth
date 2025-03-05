package main

// Custom email sender implementation
type MyEmailSender struct {
	// Any fields you need for configuration
	apiKey string
	from   string
}

// Implement the EmailSender interface methods
func (s *MyEmailSender) SendVerification(email string, params ...interface{}) error {
	// Implementation for sending verification email
	// token := params[0].(string) // Example of accessing the first parameter
	// ... your implementation logic
	return nil
}

func (s *MyEmailSender) SendPasswordReset(email string, params ...interface{}) error {
	// Implementation for sending password reset email
	// ... your implementation logic
	return nil
}

func (s *MyEmailSender) SendTwoFactorCode(email string, params ...interface{}) error {
	// Implementation for sending 2FA code via email
	// ... your implementation logic
	return nil
}

// Custom SMS sender implementation
type MySMSSender struct {
	// Any fields you need for configuration
	twilioSID   string
	twilioToken string
}

// Implement the SMSSender interface method
func (s *MySMSSender) SendTwoFactorCode(phone string, params ...interface{}) error {
	// Implementation for sending 2FA code via SMS
	// ... your implementation logic
	return nil
}
