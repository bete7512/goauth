import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ArrowLeft, Code, Zap, Shield, Download, Play } from "lucide-react";
import Link from "next/link";

export default function EchoPage() {
  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <div className="w-64 border-r bg-muted/40">
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
          <Link href="/frameworks" className="flex items-center text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Frameworks
          </Link>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <div className="container mx-auto p-8 max-w-4xl">
          <div className="mb-8">
            <div className="flex items-center space-x-4 mb-4">
              <div className="p-3 bg-blue-100 dark:bg-blue-900 rounded-lg">
                <Zap className="h-8 w-8 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <h1 className="text-3xl font-bold">Echo Framework</h1>
                <p className="text-lg text-muted-foreground">
                  High performance, extensible, minimalist Go web framework
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">High Performance</Badge>
              <Badge variant="secondary">Minimalist API</Badge>
              <Badge variant="secondary">Extensible</Badge>
              <Badge variant="secondary">Middleware Support</Badge>
            </div>
          </div>

          {/* Installation */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Download className="h-5 w-5 mr-2" />
                Installation
              </CardTitle>
              <CardDescription>
                Install Echo and go-auth dependencies
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                <div className="text-foreground">go get github.com/labstack/echo/v4</div>
                <div className="text-foreground">go get github.com/bete7512/goauth</div>
              </div>
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
                Complete example of integrating go-auth with Echo
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                <div className="text-foreground">
                  {`package main

import (
    "log"
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
)

func main() {
    // Configuration
    config := types.Config{
        JWTSecret: "your-super-secret-jwt-key-change-this",
        Database: types.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:password@localhost:5432/goauth_db",
        },
        AuthConfig: types.AuthConfig{
            Cookie: types.CookieConfig{
                Name:           "auth_token",
                AccessTokenTTL: 3600,   // 1 hour
                RefreshTokenTTL: 604800, // 7 days
                Path:           "/",
                MaxAge:         604800,
                Secure:         false,   // Set to true in production
                HttpOnly:       true,
                SameSite:       "lax",
            },
        },
    }

    // Create auth service
    authService, err := goauth.NewBuilder().
        WithConfig(config).
        Build()

    if err != nil {
        log.Fatal("Failed to create auth service:", err)
    }

    // Setup Echo
    e := echo.New()
    
    // Add middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())
    e.Use(middleware.CORS())

    // Register auth routes
    authService.RegisterEchoRoutes(e)

    // Public routes
    e.GET("/", func(c echo.Context) error {
        return c.JSON(200, map[string]string{
            "message": "Welcome to go-auth with Echo!",
            "status":  "running",
        })
    })

    // Protected routes
    api := e.Group("/api")
    api.Use(authService.EchoAuthMiddleware())
    {
        api.GET("/profile", func(c echo.Context) error {
            user := c.Get("user").(types.User)
            return c.JSON(200, map[string]interface{}{
                "user": user,
                "message": "Protected route accessed successfully",
            })
        })

        api.GET("/dashboard", func(c echo.Context) error {
            user := c.Get("user").(types.User)
            return c.JSON(200, map[string]interface{}{
                "user": user,
                "dashboard": "Welcome to your dashboard",
            })
        })
    }

    log.Println("Server starting on :8080")
    e.Start(":8080")
}`}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Advanced Features */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Advanced Features</CardTitle>
              <CardDescription>
                Learn how to use advanced go-auth features with Echo
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
                    <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                      <div className="text-foreground">
                        {`// Add OAuth providers to your config
config := types.Config{
    // ... other config
    Providers: types.ProvidersConfig{
        Enabled: []string{"google", "github"},
        Google: types.ProviderConfig{
            ClientID:     "your-google-client-id",
            ClientSecret: "your-google-client-secret",
            RedirectURL:  "https://yourapp.com/auth/google/callback",
        },
        GitHub: types.ProviderConfig{
            ClientID:     "your-github-client-id",
            ClientSecret: "your-github-client-secret",
            RedirectURL:  "https://yourapp.com/auth/github/callback",
        },
    },
}

// OAuth routes are automatically registered
// /auth/google - Google OAuth login
// /auth/github - GitHub OAuth login
// /auth/google/callback - Google OAuth callback
// /auth/github/callback - GitHub OAuth callback`}
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="middleware" className="mt-6">
                  <div className="space-y-4">
                    <h4 className="font-semibold">Custom Middleware</h4>
                    <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                      <div className="text-foreground">
                        {`// Custom middleware with role-based access
func RoleMiddleware(roles ...string) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            user := c.Get("user").(types.User)
            
            // Check if user has required role
            for _, role := range roles {
                if user.Role == role {
                    return next(c)
                }
            }
            
            return c.JSON(403, map[string]string{
                "error": "Insufficient permissions",
            })
        }
    }
}

// Usage
admin := api.Group("/admin")
admin.Use(authService.EchoAuthMiddleware())
admin.Use(RoleMiddleware("admin"))
{
    admin.GET("/users", func(c echo.Context) error {
        // Admin only endpoint
        return c.JSON(200, map[string]string{"message": "Admin panel"})
    })
}`}
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="hooks" className="mt-6">
                  <div className="space-y-4">
                    <h4 className="font-semibold">Event Hooks</h4>
                    <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                      <div className="text-foreground">
                        {`// Configure hooks for custom behavior
config := types.Config{
    // ... other config
    Hooks: types.HooksConfig{
        OnUserRegistered: func(user types.User) {
            // Send welcome email
            log.Printf("New user registered: %s", user.Email)
        },
        OnUserLoggedIn: func(user types.User) {
            // Log login activity
            log.Printf("User logged in: %s", user.Email)
        },
        OnPasswordChanged: func(user types.User) {
            // Send password change notification
            log.Printf("Password changed for user: %s", user.Email)
        },
    },
}`}
                      </div>
                    </div>
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
                Testing Your Implementation
              </CardTitle>
              <CardDescription>
                Test your Echo + go-auth integration
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">1. Start the server</h4>
                  <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                    <div className="text-foreground">go run main.go</div>
                  </div>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-2">2. Register a user</h4>
                  <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                    <div className="text-foreground">curl -X POST http://localhost:8080/auth/register \</div>
                    <div className="text-foreground ml-4">-H "Content-Type: application/json" \</div>
                    <div className="text-foreground ml-4">-d '{"email":"user@example.com","password":"password123"}'</div>
                  </div>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-2">3. Login</h4>
                  <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                    <div className="text-foreground">curl -X POST http://localhost:8080/auth/login \</div>
                    <div className="text-foreground ml-4">-H "Content-Type: application/json" \</div>
                    <div className="text-foreground ml-4">-d '{"email":"user@example.com","password":"password123"}'</div>
                  </div>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-2">4. Access protected route</h4>
                  <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                    <div className="text-foreground">curl -X GET http://localhost:8080/api/profile \</div>
                    <div className="text-foreground ml-4">-H "Cookie: auth_token=YOUR_TOKEN_HERE"</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Best Practices */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Best Practices</CardTitle>
              <CardDescription>
                Follow these best practices for production deployments
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="p-4 border rounded-lg">
                  <h4 className="font-semibold mb-2">🔒 Security</h4>
                  <ul className="text-sm space-y-1">
                    <li>• Set <code className="bg-muted px-1 rounded">Secure: true</code> in production</li>
                    <li>• Use strong JWT secrets (32+ characters)</li>
                    <li>• Enable HTTPS in production</li>
                    <li>• Configure proper CORS settings</li>
                  </ul>
                </div>
                
                <div className="p-4 border rounded-lg">
                  <h4 className="font-semibold mb-2">⚡ Performance</h4>
                  <ul className="text-sm space-y-1">
                    <li>• Use connection pooling for database</li>
                    <li>• Enable rate limiting</li>
                    <li>• Use Redis for session storage</li>
                    <li>• Monitor memory usage</li>
                  </ul>
                </div>
                
                <div className="p-4 border rounded-lg">
                  <h4 className="font-semibold mb-2">🔧 Configuration</h4>
                  <ul className="text-sm space-y-1">
                    <li>• Use environment variables for secrets</li>
                    <li>• Separate config for different environments</li>
                    <li>• Enable logging and monitoring</li>
                    <li>• Set up proper error handling</li>
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Navigation */}
          <div className="flex justify-between">
            <Button asChild variant="outline">
              <Link href="/frameworks">
                ← Back to Frameworks
              </Link>
            </Button>
            <Button asChild>
              <Link href="/frameworks/gin">
                Next: Gin Framework →
              </Link>
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
} 