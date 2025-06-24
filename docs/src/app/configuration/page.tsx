"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ArrowLeft, Shield, Settings, Database, Lock, Mail, MessageSquare, Globe } from "lucide-react";
import { CodeBlock, CodeBlockWithLines } from "@/components/ui/code-block";
import Link from "next/link";

const ConfigurationPage = () => {
  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="w-64 border-r bg-muted/40">
        <div className="p-6">
          <div className="flex items-center space-x-2">
            <Shield className="h-6 w-6 text-primary" />
            <h1 className="text-xl font-bold">go-auth</h1>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            Authentication library for Go
          </p>
        </div>
        
        <div className="p-4">
          <Link href="/" className="flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Home
          </Link>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <div className="container mx-auto p-8 max-w-6xl">
          <header className="mb-8">
            <div className="flex items-center space-x-2 mb-4">
              <Badge variant="secondary" className="text-sm">
                <Settings className="h-3 w-3 mr-1" />
                Configuration Guide
              </Badge>
            </div>
            <h1 className="text-3xl font-bold mb-4">Configuration</h1>
            <p className="text-lg text-muted-foreground">
              Learn how to configure go-auth with all available options and features.
            </p>
          </header>

          <Tabs defaultValue="basic" className="space-y-6">
            <TabsList className="grid w-full grid-cols-6">
              <TabsTrigger value="basic">Basic</TabsTrigger>
              <TabsTrigger value="auth">Auth</TabsTrigger>
              <TabsTrigger value="database">Database</TabsTrigger>
              <TabsTrigger value="security">Security</TabsTrigger>
              <TabsTrigger value="notifications">Notifications</TabsTrigger>
              <TabsTrigger value="oauth">OAuth</TabsTrigger>
            </TabsList>

            {/* Basic Configuration */}
            <TabsContent value="basic" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Globe className="h-5 w-5 text-blue-500 mr-2" />
                    Basic Configuration
                  </CardTitle>
                  <CardDescription>
                    Essential configuration for your application
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <CodeBlockWithLines language="go" title="Basic Config">
{`config := config.Config{
    App: config.AppConfig{
        BasePath:    "/auth",           // Base path for all auth routes
        Domain:      "localhost",       // Your application domain
        FrontendURL: "http://localhost:3000", // Frontend URL for redirects
        Swagger: config.SwaggerConfig{
            Enable:      true,          // Enable Swagger documentation
            Title:       "My API",      // API title
            Version:     "1.0.0",       // API version
            DocPath:     "/docs",       // Swagger docs path
            Description: "API Documentation",
            Host:        "localhost:8080",
        },
    },
    Database: config.DatabaseConfig{
        Type:        "postgres",        // postgres, mysql, mongodb, sqlite
        URL:         "postgres://user:pass@localhost/dbname?sslmode=disable",
        AutoMigrate: true,              // Auto migrate database tables
    },
    Features: config.FeaturesConfig{
        EnableRateLimiter:   false,     // Enable rate limiting
        EnableRecaptcha:     false,     // Enable reCAPTCHA
        EnableCustomJWT:     false,     // Enable custom JWT claims
        EnableCustomStorage: false,     // Enable custom storage repository
    },
}`}
                  </CodeBlockWithLines>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Auth Configuration */}
            <TabsContent value="auth" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Lock className="h-5 w-5 text-green-500 mr-2" />
                    Authentication Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure JWT, tokens, methods, and policies
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <CodeBlockWithLines language="go" title="Auth Config">
{`AuthConfig: config.AuthConfig{
    // JWT Configuration
    JWT: config.JWTConfig{
        Secret:             "your-secret-key-32-chars-long",
        AccessTokenTTL:     15 * time.Minute,
        RefreshTokenTTL:    7 * 24 * time.Hour,
        EnableCustomClaims: false,
        ClaimsProvider:     nil, // Custom claims provider
    },
    
    // Token TTLs
    Tokens: config.TokenConfig{
        HashSaltLength:       16,
        PhoneVerificationTTL: 10 * time.Minute,
        EmailVerificationTTL: 1 * time.Hour,
        PasswordResetTTL:     10 * time.Minute,
        TwoFactorTTL:         10 * time.Minute,
        MagicLinkTTL:         10 * time.Minute,
    },
    
    // Authentication Methods
    Methods: config.AuthMethodsConfig{
        Type:                  config.AuthenticationTypeEmail, // email, phone, username
        EnableTwoFactor:       true,
        EnableMultiSession:    false,
        EnableMagicLink:       false,
        EnableSmsVerification: false,
        TwoFactorMethod:       "email", // email, sms, app
        
        EmailVerification: config.EmailVerificationConfig{
            EnableOnSignup:   true,
            VerificationURL:  "http://localhost:3000/verify",
            SendWelcomeEmail: false,
        },
        
        PhoneVerification: config.PhoneVerificationConfig{
            EnableOnSignup:      true,
            UniquePhoneNumber:   false,
            PhoneColumnRequired: true,
            PhoneRequired:       true,
        },
    },
    
    // Password Policy
    PasswordPolicy: config.PasswordPolicy{
        HashSaltLength: 16,
        MinLength:      8,
        RequireUpper:   true,
        RequireLower:   true,
        RequireNumber:  true,
        RequireSpecial: true,
    },
    
    // Cookie Configuration
    Cookie: config.CookieConfig{
        Name:     "auth_token",
        Path:     "/",
        MaxAge:   86400,
        Secure:   false,     // Set to true in production
        HttpOnly: true,
        SameSite: 1,         // http.SameSiteLaxMode
    },
    
    // Email Domain Restrictions
    BlockedEmailDomains: []string{"temp-mail.org", "10minutemail.com"},
    AllowedEmailDomains: []string{}, // Empty means all domains allowed
}`}
                  </CodeBlockWithLines>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Database Configuration */}
            <TabsContent value="database" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Database className="h-5 w-5 text-purple-500 mr-2" />
                    Database Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure database connections and storage
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    
                    {/* PostgreSQL */}
                    <div>
                      <h4 className="font-semibold mb-3 text-blue-600">PostgreSQL</h4>
                      <CodeBlock language="go" title="PostgreSQL Config">
{`Database: config.DatabaseConfig{
    Type:        "postgres",
    URL:         "postgres://user:password@localhost:5432/dbname?sslmode=disable",
    AutoMigrate: true,
}`}
                      </CodeBlock>
                    </div>

                    {/* MySQL */}
                    <div>
                      <h4 className="font-semibold mb-3 text-orange-600">MySQL</h4>
                      <CodeBlock language="go" title="MySQL Config">
{`Database: config.DatabaseConfig{
    Type:        "mysql",
    URL:         "user:password@tcp(localhost:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local",
    AutoMigrate: true,
}`}
                      </CodeBlock>
                    </div>

                    {/* MongoDB */}
                    <div>
                      <h4 className="font-semibold mb-3 text-green-600">MongoDB</h4>
                      <CodeBlock language="go" title="MongoDB Config">
{`Database: config.DatabaseConfig{
    Type:        "mongodb",
    URL:         "mongodb://localhost:27017/dbname",
    AutoMigrate: true,
}`}
                      </CodeBlock>
                    </div>

                    {/* SQLite */}
                    <div>
                      <h4 className="font-semibold mb-3 text-gray-600">SQLite</h4>
                      <CodeBlock language="go" title="SQLite Config">
{`Database: config.DatabaseConfig{
    Type:        "sqlite",
    URL:         "file:./auth.db?cache=shared&_fk=1",
    AutoMigrate: true,
}`}
                      </CodeBlock>
                    </div>

                    {/* Custom Storage */}
                    <div>
                      <h4 className="font-semibold mb-3 text-red-600">Custom Storage</h4>
                      <CodeBlock language="go" title="Custom Storage Config">
{`// Enable custom storage
Features: config.FeaturesConfig{
    EnableCustomStorage: true,
},

// Use builder with custom repository
auth, err := goauth.NewBuilder().
    WithConfig(config).
    WithRepositoryFactory(customFactory).
    Build()`}
                      </CodeBlock>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Security Configuration */}
            <TabsContent value="security" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Shield className="h-5 w-5 text-red-500 mr-2" />
                    Security Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure rate limiting, reCAPTCHA, and security features
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    
                    {/* Rate Limiting */}
                    <div>
                      <h4 className="font-semibold mb-3 text-blue-600">Rate Limiting</h4>
                      <CodeBlock language="go" title="Rate Limiter Config">
{`Security: config.SecurityConfig{
    RateLimiter: config.RateLimiterConfig{
        Enabled: true,
        Type:    config.MemoryRateLimiter, // memory, redis
        Routes: map[string]config.LimiterConfig{
            config.RouteRegister: {
                WindowSize:    30 * time.Second,
                MaxRequests:   10,
                BlockDuration: 1 * time.Minute,
            },
            config.RouteLogin: {
                WindowSize:    1 * time.Minute,
                MaxRequests:   5,
                BlockDuration: 1 * time.Minute,
            },
            "global": {
                WindowSize:    1 * time.Minute,
                MaxRequests:   100,
                BlockDuration: 5 * time.Minute,
            },
        },
    },
}`}
                      </CodeBlock>
                    </div>

                    {/* reCAPTCHA */}
                    <div>
                      <h4 className="font-semibold mb-3 text-green-600">reCAPTCHA</h4>
                      <CodeBlock language="go" title="reCAPTCHA Config">
{`Security: config.SecurityConfig{
    Recaptcha: config.RecaptchaConfig{
        Enabled:   true,
        Provider:  "google", // google, cloudflare
        SecretKey: "your-recaptcha-secret-key",
        SiteKey:   "your-recaptcha-site-key",
        APIURL:    "https://www.google.com/recaptcha/api/siteverify",
        Routes: map[string]bool{
            config.RouteRegister: true,
            config.RouteLogin:    true,
            config.RouteForgotPassword: true,
        },
    },
}`}
                      </CodeBlock>
                    </div>

                    {/* Redis Rate Limiting */}
                    <div>
                      <h4 className="font-semibold mb-3 text-purple-600">Redis Rate Limiting</h4>
                      <CodeBlock language="go" title="Redis Config">
{`// Redis Configuration
Redis: config.RedisConfig{
    Host:     "localhost",
    Port:     6379,
    Database: 0,
    Password: "",
},

// Rate Limiter with Redis
Security: config.SecurityConfig{
    RateLimiter: config.RateLimiterConfig{
        Enabled: true,
        Type:    config.RedisRateLimiter,
        Routes:  map[string]config.LimiterConfig{
            // ... route configurations
        },
    },
}`}
                      </CodeBlock>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Notifications Configuration */}
            <TabsContent value="notifications" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Mail className="h-5 w-5 text-blue-500 mr-2" />
                    Email Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure email providers and templates
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    
                    {/* SendGrid */}
                    <div>
                      <h4 className="font-semibold mb-3 text-blue-600">SendGrid</h4>
                      <CodeBlock language="go" title="SendGrid Config">
{`Email: config.EmailConfig{
    Sender: config.EmailSenderConfig{
        Type:         "sendgrid",
        FromEmail:    "noreply@yourdomain.com",
        FromName:     "Your App Name",
        SupportEmail: "support@yourdomain.com",
    },
    SendGrid: config.SendGridConfig{
        APIKey: "your-sendgrid-api-key",
    },
    Branding: config.EmailBrandingConfig{
        LogoURL:      "https://yourdomain.com/logo.png",
        CompanyName:  "Your Company",
        PrimaryColor: "#007bff",
    },
}`}
                      </CodeBlock>
                    </div>

                    {/* AWS SES */}
                    <div>
                      <h4 className="font-semibold mb-3 text-orange-600">AWS SES</h4>
                      <CodeBlock language="go" title="AWS SES Config">
{`Email: config.EmailConfig{
    Sender: config.EmailSenderConfig{
        Type:         "ses",
        FromEmail:    "noreply@yourdomain.com",
        FromName:     "Your App Name",
        SupportEmail: "support@yourdomain.com",
    },
    SES: config.SESConfig{
        Region:          "us-east-1",
        AccessKeyID:     "your-access-key",
        SecretAccessKey: "your-secret-key",
    },
}`}
                      </CodeBlock>
                    </div>

                    {/* Custom Email Sender */}
                    <div>
                      <h4 className="font-semibold mb-3 text-green-600">Custom Email Sender</h4>
                      <CodeBlock language="go" title="Custom Email Config">
{`Email: config.EmailConfig{
    Sender: config.EmailSenderConfig{
        Type:         "custom",
        FromEmail:    "noreply@yourdomain.com",
        FromName:     "Your App Name",
        SupportEmail: "support@yourdomain.com",
        CustomSender: &MyEmailSender{}, // Implement EmailSenderInterface
    },
}`}
                      </CodeBlock>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <MessageSquare className="h-5 w-5 text-green-500 mr-2" />
                    SMS Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure SMS providers for phone verification
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    
                    {/* Twilio */}
                    <div>
                      <h4 className="font-semibold mb-3 text-blue-600">Twilio</h4>
                      <CodeBlock language="go" title="Twilio Config">
{`SMS: config.SMSConfig{
    Twilio: config.TwilioConfig{
        AccountSID: "your-twilio-account-sid",
        AuthToken:  "your-twilio-auth-token",
        FromNumber: "+1234567890",
    },
    CompanyName:  "Your Company",
    CustomSender: nil,
}`}
                      </CodeBlock>
                    </div>

                    {/* Custom SMS Sender */}
                    <div>
                      <h4 className="font-semibold mb-3 text-purple-600">Custom SMS Sender</h4>
                      <CodeBlock language="go" title="Custom SMS Config">
{`SMS: config.SMSConfig{
    Twilio: config.TwilioConfig{
        AccountSID: "",
        AuthToken:  "",
        FromNumber: "",
    },
    CompanyName:  "Your Company",
    CustomSender: &MySMSSender{}, // Implement SMSSenderInterface
}`}
                      </CodeBlock>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* OAuth Configuration */}
            <TabsContent value="oauth" className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Globe className="h-5 w-5 text-purple-500 mr-2" />
                    OAuth Providers
                  </CardTitle>
                  <CardDescription>
                    Configure OAuth providers for social login
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    
                    {/* Google OAuth */}
                    <div>
                      <h4 className="font-semibold mb-3 text-red-600">Google OAuth</h4>
                      <CodeBlock language="go" title="Google OAuth Config">
{`Providers: config.ProvidersConfig{
    Enabled: []config.AuthProvider{config.Google},
    Google: config.ProviderConfig{
        ClientID:     "your-google-client-id",
        ClientSecret: "your-google-client-secret",
        RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
        Scopes:       []string{"email", "profile"},
    },
}`}
                      </CodeBlock>
                    </div>

                    {/* GitHub OAuth */}
                    <div>
                      <h4 className="font-semibold mb-3 text-gray-600">GitHub OAuth</h4>
                      <CodeBlock language="go" title="GitHub OAuth Config">
{`Providers: config.ProvidersConfig{
    Enabled: []config.AuthProvider{config.GitHub},
    GitHub: config.ProviderConfig{
        ClientID:     "your-github-client-id",
        ClientSecret: "your-github-client-secret",
        RedirectURL:  "http://localhost:8080/auth/oauth/github/callback",
        Scopes:       []string{"user:email", "read:user"},
    },
}`}
                      </CodeBlock>
                    </div>

                    {/* Multiple Providers */}
                    <div>
                      <h4 className="font-semibold mb-3 text-blue-600">Multiple Providers</h4>
                      <CodeBlock language="go" title="Multiple OAuth Config">
{`Providers: config.ProvidersConfig{
    Enabled: []config.AuthProvider{
        config.Google, 
        config.GitHub, 
        config.Facebook,
        config.Microsoft,
        config.Apple,
        config.Discord,
    },
    Google: config.ProviderConfig{
        ClientID:     "google-client-id",
        ClientSecret: "google-secret",
        RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
    },
    GitHub: config.ProviderConfig{
        ClientID:     "github-client-id",
        ClientSecret: "github-secret",
        RedirectURL:  "http://localhost:8080/auth/oauth/github/callback",
    },
    Facebook: config.ProviderConfig{
        ClientID:     "facebook-client-id",
        ClientSecret: "facebook-secret",
        RedirectURL:  "http://localhost:8080/auth/oauth/facebook/callback",
    },
    // ... other providers
}`}
                      </CodeBlock>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  );
};

export default ConfigurationPage;