"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Shield, Zap, Star, CheckCircle } from "lucide-react";
import { CodeBlock, CodeBlockWithLines } from "@/components/ui/code-block";
import Link from "next/link";

const QuickstartPage = () => {
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
        <div className="container mx-auto p-8 max-w-4xl">
          <header className="mb-8">
            <div className="flex items-center space-x-2 mb-4">
              <Badge variant="secondary" className="text-sm">
                <Star className="h-3 w-3 mr-1" />
                New Features
              </Badge>
              <Badge variant="secondary" className="text-sm">
                <Zap className="h-3 w-3 mr-1" />
                Builder Pattern
              </Badge>
            </div>
            <h1 className="text-3xl font-bold mb-4">Quick Start Guide</h1>
            <p className="text-lg text-muted-foreground">
              Build your first authenticated application with go-auth in minutes using the new builder pattern and manual route registration.
            </p>
          </header>

          {/* Installation */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center">
                <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
                Installation
              </CardTitle>
              <CardDescription>
                Install go-auth and get started quickly
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold mb-3">1. Install go-auth</h3>
                  <CodeBlock language="bash" title="Terminal">
                    go get github.com/bete7512/goauth
                  </CodeBlock>
                </div>
                
                <div>
                  <h3 className="text-lg font-semibold mb-3">2. Choose your framework</h3>
                  <CodeBlock language="bash" title="Install Framework">
{`# Gin Framework
go get github.com/gin-gonic/gin

# Echo Framework  
go get github.com/labstack/echo/v4

# Chi Framework
go get github.com/go-chi/chi/v5

# Fiber Framework
go get github.com/gofiber/fiber/v2

# Gorilla Mux
go get github.com/gorilla/mux`}
                  </CodeBlock>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Basic Setup */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Zap className="h-5 w-5 text-blue-500 mr-2" />
                Basic Setup with Builder Pattern
              </CardTitle>
              <CardDescription>
                Create a simple authentication server using the new builder pattern
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h3 className="text-lg font-semibold mb-3">Create main.go</h3>
                  <CodeBlockWithLines language="go" title="main.go">
{`package main

import (
    "log"
    "time"

    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/config"
    "github.com/gin-gonic/gin"
)

func main() {
    // Create configuration
    config := config.Config{
        App: config.AppConfig{
            BasePath:    "/auth",
            Domain:      "localhost",
            FrontendURL: "http://localhost:3000",
        },
        Database: config.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:pass@localhost/dbname?sslmode=disable",
        },
        AuthConfig: config.AuthConfig{
            JWT: config.JWTConfig{
                Secret:             "your-secret-key-32-chars-long",
                AccessTokenTTL:     15 * time.Minute,
                RefreshTokenTTL:    7 * 24 * time.Hour,
                EnableCustomClaims: false,
            },
            Tokens: config.TokenConfig{
                HashSaltLength:       16,
                PhoneVerificationTTL: 10 * time.Minute,
                EmailVerificationTTL: 1 * time.Hour,
                PasswordResetTTL:     10 * time.Minute,
                TwoFactorTTL:         10 * time.Minute,
                MagicLinkTTL:         10 * time.Minute,
            },
            Methods: config.AuthMethodsConfig{
                Type:                  config.AuthenticationTypeEmail,
                EnableTwoFactor:       true,
                EnableMultiSession:    false,
                EnableMagicLink:       false,
                EnableSmsVerification: false,
                TwoFactorMethod:       "email",
                EmailVerification: config.EmailVerificationConfig{
                    EnableOnSignup:   true,
                    VerificationURL:  "http://localhost:3000/verify",
                    SendWelcomeEmail: false,
                },
            },
            PasswordPolicy: config.PasswordPolicy{
                HashSaltLength: 16,
                MinLength:      8,
                RequireUpper:   true,
                RequireLower:   true,
                RequireNumber:  true,
                RequireSpecial: true,
            },
            Cookie: config.CookieConfig{
                Name:     "auth_token",
                Path:     "/",
                MaxAge:   86400,
                Secure:   false,
                HttpOnly: true,
                SameSite: 1,
            },
        },
        Features: config.FeaturesConfig{
            EnableRateLimiter:   false,
            EnableRecaptcha:     false,
            EnableCustomJWT:     false,
            EnableCustomStorage: false,
        },
        Security: config.SecurityConfig{
            RateLimiter: config.RateLimiterConfig{
                Enabled: false,
                Type:    config.MemoryRateLimiter,
                Routes:  make(map[string]config.LimiterConfig),
            },
            Recaptcha: config.RecaptchaConfig{
                Enabled:   false,
                SecretKey: "",
                SiteKey:   "",
                Provider:  "google",
                APIURL:    "",
                Routes:    make(map[string]bool),
            },
        },
        Email: config.EmailConfig{
            Sender: config.EmailSenderConfig{
                Type:         "sendgrid",
                FromEmail:    "noreply@example.com",
                FromName:     "My App",
                SupportEmail: "support@example.com",
                CustomSender: nil,
            },
        },
        SMS: config.SMSConfig{
            CompanyName:  "My App",
            CustomSender: nil,
        },
        Providers: config.ProvidersConfig{
            Enabled: []config.AuthProvider{},
        },
    }

    // Initialize GoAuth using the builder pattern
    auth, err := goauth.NewBuilder().WithConfig(config).Build()
    if err != nil {
        log.Fatal(err)
    }

    // Setup Gin router
    router := gin.Default()

    // Register auth routes manually (recommended approach)
    authRoutes := auth.GetRoutes()
    for _, route := range authRoutes {
        handler := auth.GetWrappedHandler(route)
        ginHandler := gin.WrapF(handler)
        
        switch route.Method {
        case "GET":
            router.GET(route.Path, ginHandler)
        case "POST":
            router.POST(route.Path, ginHandler)
        case "PUT":
            router.PUT(route.Path, ginHandler)
        case "DELETE":
            router.DELETE(route.Path, ginHandler)
        }
    }

    log.Println("Server starting on :8080")
    router.Run(":8080")
}`}
                  </CodeBlockWithLines>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Framework Examples */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Framework Integration Examples</CardTitle>
              <CardDescription>
                See how to integrate with different frameworks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                
                {/* Echo Framework */}
                <div>
                  <h4 className="font-semibold mb-3 text-blue-600">Echo Framework</h4>
                  <CodeBlock language="go" title="Echo Integration">
{`e := echo.New()

// Register auth routes manually
authRoutes := auth.GetRoutes()
for _, route := range authRoutes {
    handler := auth.GetWrappedHandler(route)
    e.Any(route.Path, echo.WrapHandler(http.HandlerFunc(handler)))
}

e.Start(":8080")`}
                  </CodeBlock>
                </div>

                {/* Chi Framework */}
                <div>
                  <h4 className="font-semibold mb-3 text-green-600">Chi Framework</h4>
                  <CodeBlock language="go" title="Chi Integration">
{`r := chi.NewRouter()

// Register auth routes manually
authRoutes := auth.GetRoutes()
for _, route := range authRoutes {
    handler := auth.GetWrappedHandler(route)
    r.HandleFunc(route.Method+" "+route.Path, handler)
}

http.ListenAndServe(":8080", r)`}
                  </CodeBlock>
                </div>

                {/* Fiber Framework */}
                <div>
                  <h4 className="font-semibold mb-3 text-purple-600">Fiber Framework</h4>
                  <CodeBlock language="go" title="Fiber Integration">
{`app := fiber.New()

// Register auth routes manually
authRoutes := auth.GetRoutes()
for _, route := range authRoutes {
    handler := auth.GetWrappedHandler(route)
    fiberHandler := adaptor.HTTPHandler(http.HandlerFunc(handler))
    
    switch route.Method {
    case "GET":
        app.Get(route.Path, fiberHandler)
    case "POST":
        app.Post(route.Path, fiberHandler)
    case "PUT":
        app.Put(route.Path, fiberHandler)
    case "DELETE":
        app.Delete(route.Path, fiberHandler)
    }
}

app.Listen(":8080")`}
                  </CodeBlock>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Database Setup */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Database Setup</CardTitle>
              <CardDescription>
                Set up your database for user storage
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div>
                  <h4 className="font-semibold mb-3">PostgreSQL with Docker</h4>
                  <CodeBlock language="bash" title="Docker Command">
{`docker run --name postgres \\
  -e POSTGRES_PASSWORD=password \\
  -e POSTGRES_DB=goauth_db \\
  -p 5432:5432 \\
  -d postgres:15`}
                  </CodeBlock>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-3">Connection String</h4>
                  <CodeBlock language="text" title="Database URL">
                    postgres://postgres:password@localhost:5432/goauth_db
                  </CodeBlock>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Testing */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Testing Your Setup</CardTitle>
              <CardDescription>
                Test your authentication endpoints
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div>
                  <h4 className="font-semibold mb-3">Register a new user</h4>
                  <CodeBlock language="bash" title="Register User">
{`curl -X POST http://localhost:8080/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'`}
                  </CodeBlock>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-3">Login</h4>
                  <CodeBlock language="bash" title="Login">
{`curl -X POST http://localhost:8080/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'`}
                  </CodeBlock>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-3">Get user profile</h4>
                  <CodeBlock language="bash" title="Get Profile">
{`curl -X GET http://localhost:8080/auth/me \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"`}
                  </CodeBlock>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Next Steps */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Next Steps</CardTitle>
              <CardDescription>
                Explore advanced features and configurations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Link href="/configuration">
                  <Card className="hover:shadow-md transition-shadow cursor-pointer">
                    <CardContent className="p-4">
                      <h4 className="font-semibold mb-2">Configuration</h4>
                      <p className="text-sm text-muted-foreground">
                        Learn about advanced configuration options
                      </p>
                    </CardContent>
                  </Card>
                </Link>
                
                <Link href="/features/oauth">
                  <Card className="hover:shadow-md transition-shadow cursor-pointer">
                    <CardContent className="p-4">
                      <h4 className="font-semibold mb-2">OAuth Providers</h4>
                      <p className="text-sm text-muted-foreground">
                        Set up Google, GitHub, and other OAuth providers
                      </p>
                    </CardContent>
                  </Card>
                </Link>
                
                <Link href="/features/two-factor">
                  <Card className="hover:shadow-md transition-shadow cursor-pointer">
                    <CardContent className="p-4">
                      <h4 className="font-semibold mb-2">Two-Factor Auth</h4>
                      <p className="text-sm text-muted-foreground">
                        Enable 2FA for enhanced security
                      </p>
                    </CardContent>
                  </Card>
                </Link>
                
                <Link href="/api/endpoints">
                  <Card className="hover:shadow-md transition-shadow cursor-pointer">
                    <CardContent className="p-4">
                      <h4 className="font-semibold mb-2">API Reference</h4>
                      <p className="text-sm text-muted-foreground">
                        Complete API documentation
                      </p>
                    </CardContent>
                  </Card>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default QuickstartPage;