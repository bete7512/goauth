"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ArrowLeft, Code, Zap, Shield, Download, Play } from "lucide-react";
import { CodeBlock, CodeBlockWithLines } from "@/components/ui/code-block";
import Link from "next/link";

export default function GinPage() {
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
          <Link href="/frameworks" className="flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Frameworks
          </Link>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <div className="container mx-auto p-8 max-w-4xl">
          <header className="mb-8">
            <div className="flex items-center space-x-4 mb-4">
              <div className="p-3 bg-green-100 dark:bg-green-900 rounded-lg">
                <Zap className="h-8 w-8 text-green-600 dark:text-green-400" />
              </div>
              <div>
                <h1 className="text-3xl font-bold">Gin Framework</h1>
                <p className="text-lg text-muted-foreground">
                  Fast HTTP web framework with excellent performance
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">High Performance</Badge>
              <Badge variant="secondary">Easy Integration</Badge>
              <Badge variant="secondary">Middleware Support</Badge>
              <Badge variant="secondary">Popular</Badge>
            </div>
          </header>

          {/* Installation */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Download className="h-5 w-5 mr-2" />
                Installation
              </CardTitle>
              <CardDescription>
                Install Gin and go-auth dependencies
              </CardDescription>
            </CardHeader>
            <CardContent>
              <CodeBlock language="bash" title="Install Dependencies">
{`go get github.com/gin-gonic/gin
go get github.com/bete7512/goauth`}
              </CodeBlock>
            </CardContent>
          </Card>

          {/* Basic Implementation */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Code className="h-5 w-5 mr-2" />
                Basic Implementation
              </CardTitle>
              <CardDescription>
                Complete example of integrating go-auth with Gin using the new builder pattern
              </CardDescription>
            </CardHeader>
            <CardContent>
              <CodeBlockWithLines language="go" title="main.go">
{`package main

import (
    "log"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/config"
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
            Type:        "postgres",
            URL:         "postgres://user:password@localhost:5432/goauth_db?sslmode=disable",
            AutoMigrate: true,
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
                Secure:   false,     // Set to true in production
                HttpOnly: true,
                SameSite: 1,         // http.SameSiteLaxMode
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
    
    // Add middleware
    router.Use(gin.Logger())
    router.Use(gin.Recovery())

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

    // Public routes
    router.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "Welcome to go-auth with Gin!",
            "status":  "running",
        })
    })

    // Protected routes
    protected := router.Group("/api")
    protected.Use(auth.GetGinAuthMiddleware())
    {
        protected.GET("/profile", func(c *gin.Context) {
            userID := c.MustGet("user_id").(string)
            c.JSON(200, gin.H{
                "user_id": userID,
                "message": "Protected route accessed successfully",
            })
        })

        protected.GET("/dashboard", func(c *gin.Context) {
            userID := c.MustGet("user_id").(string)
            c.JSON(200, gin.H{
                "user_id":   userID,
                "dashboard": "Welcome to your dashboard",
            })
        })
    }

    log.Println("Server starting on :8080")
    router.Run(":8080")
}`}
              </CodeBlockWithLines>
            </CardContent>
          </Card>

          {/* Advanced Features */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Advanced Features</CardTitle>
              <CardDescription>
                Learn how to use advanced go-auth features with Gin
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="oauth" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="oauth">OAuth</TabsTrigger>
                  <TabsTrigger value="middleware">Middleware</TabsTrigger>
                  <TabsTrigger value="hooks">Hooks</TabsTrigger>
                </TabsList>

                <TabsContent value="oauth" className="mt-6">
                  <div className="space-y-4">
                    <h4 className="font-semibold">OAuth Configuration</h4>
                    <CodeBlock language="go" title="OAuth Setup">
{`// Add OAuth providers to your config
config := config.Config{
    // ... other config
    Providers: config.ProvidersConfig{
        Enabled: []config.AuthProvider{config.Google, config.GitHub},
        Google: config.ProviderConfig{
            ClientID:     "your-google-client-id",
            ClientSecret: "your-google-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
            Scopes:       []string{"email", "profile"},
        },
        GitHub: config.ProviderConfig{
            ClientID:     "your-github-client-id",
            ClientSecret: "your-github-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/github/callback",
            Scopes:       []string{"user:email", "read:user"},
        },
    },
}

// OAuth routes are automatically registered with your auth routes
// Users can now login with:
// GET /auth/oauth/google
// GET /auth/oauth/github`}
                    </CodeBlock>
                  </div>
                </TabsContent>

                <TabsContent value="middleware" className="mt-6">
                  <div className="space-y-4">
                    <h4 className="font-semibold">Custom Middleware</h4>
                    <CodeBlock language="go" title="Custom Middleware">
{`// Create custom middleware that uses go-auth
func CustomAuthMiddleware(auth *goauth.Auth) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Get user ID from context (set by go-auth middleware)
        userID, exists := c.Get("user_id")
        if !exists {
            c.JSON(401, gin.H{"error": "Unauthorized"})
            c.Abort()
            return
        }

        // Add custom logic here
        c.Set("custom_user_id", userID)
        c.Next()
    }
}

// Use in your routes
protected := router.Group("/api")
protected.Use(auth.GetGinAuthMiddleware())
protected.Use(CustomAuthMiddleware(auth))
{
    protected.GET("/custom", func(c *gin.Context) {
        customUserID := c.MustGet("custom_user_id").(string)
        c.JSON(200, gin.H{"custom_user_id": customUserID})
    })
}`}
                    </CodeBlock>
                  </div>
                </TabsContent>

                <TabsContent value="hooks" className="mt-6">
                  <div className="space-y-4">
                    <h4 className="font-semibold">Event Hooks</h4>
                    <CodeBlock language="go" title="Event Hooks">
{`// Use builder pattern with custom hooks
auth, err := goauth.NewBuilder().
    WithConfig(config).
    WithHooks(&goauth.Hooks{
        OnUserRegistered: func(user *types.User) {
            log.Printf("New user registered: %s", user.Email)
            // Send welcome email, create profile, etc.
        },
        OnUserLoggedIn: func(user *types.User) {
            log.Printf("User logged in: %s", user.Email)
            // Update last login time, log activity, etc.
        },
        OnPasswordChanged: func(user *types.User) {
            log.Printf("Password changed for user: %s", user.Email)
            // Send password change notification, etc.
        },
    }).
    Build()`}
                    </CodeBlock>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          {/* Testing */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Play className="h-5 w-5 mr-2" />
                Testing Your Setup
              </CardTitle>
              <CardDescription>
                Test your Gin + go-auth integration
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-3">1. Start the server</h4>
                  <CodeBlock language="bash" title="Start Server">
                    go run main.go
                  </CodeBlock>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-3">2. Test registration</h4>
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
                  <h4 className="font-semibold mb-3">3. Test login</h4>
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
                  <h4 className="font-semibold mb-3">4. Test protected route</h4>
                  <CodeBlock language="bash" title="Protected Route">
{`curl -X GET http://localhost:8080/api/profile \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"`}
                  </CodeBlock>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Next Steps */}
          <Card>
            <CardHeader>
              <CardTitle>Next Steps</CardTitle>
              <CardDescription>
                Explore more features and configurations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/configuration">
                    <span className="font-semibold">Configuration Guide</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Learn about all configuration options
                    </span>
                  </Link>
                </Button>
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/features/oauth">
                    <span className="font-semibold">OAuth Providers</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Set up social login with OAuth
                    </span>
                  </Link>
                </Button>
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/api/endpoints">
                    <span className="font-semibold">API Reference</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Complete API documentation
                    </span>
                  </Link>
                </Button>
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/examples/basic-auth">
                    <span className="font-semibold">Examples</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      More examples and use cases
                    </span>
                  </Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
} 