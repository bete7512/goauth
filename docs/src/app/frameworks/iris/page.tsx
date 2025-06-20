import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Code, Zap, Shield, Download, Play } from "lucide-react";
import Link from "next/link";

export default function IrisPage() {
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
              <div className="p-3 bg-pink-100 dark:bg-pink-900 rounded-lg">
                <Zap className="h-8 w-8 text-pink-600 dark:text-pink-400" />
              </div>
              <div>
                <h1 className="text-3xl font-bold">Iris Framework</h1>
                <p className="text-lg text-muted-foreground">
                  Fast, simple yet efficient HTTP web framework
                </p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">Fast</Badge>
              <Badge variant="secondary">Feature-rich</Badge>
              <Badge variant="secondary">Simple API</Badge>
              <Badge variant="secondary">High Performance</Badge>
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
                Install Iris and go-auth dependencies
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                <div className="text-foreground">go get github.com/kataras/iris/v12</div>
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
                Complete example of integrating go-auth with Iris
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                <div className="text-foreground">
                  {`package main

import (
    "log"
    "github.com/kataras/iris/v12"
    "github.com/kataras/iris/v12/middleware/logger"
    "github.com/kataras/iris/v12/middleware/recover"
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

    // Setup Iris
    app := iris.New()
    
    // Add middleware
    app.Use(logger.New())
    app.Use(recover.New())

    // Register auth routes
    authService.RegisterIrisRoutes(app)

    // Public routes
    app.Get("/", func(ctx iris.Context) {
        ctx.JSON(iris.Map{
            "message": "Welcome to go-auth with Iris!",
            "status":  "running",
        })
    })

    // Protected routes
    api := app.Party("/api")
    api.Use(authService.IrisAuthMiddleware())
    {
        api.Get("/profile", func(ctx iris.Context) {
            user := ctx.Values().Get("user").(types.User)
            ctx.JSON(iris.Map{
                "user": user,
                "message": "Protected route accessed successfully",
            })
        })

        api.Get("/dashboard", func(ctx iris.Context) {
            user := ctx.Values().Get("user").(types.User)
            ctx.JSON(iris.Map{
                "user": user,
                "dashboard": "Welcome to your dashboard",
            })
        })
    }

    log.Println("Server starting on :8080")
    app.Listen(":8080")
}`}
                </div>
              </div>
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
                Test your Iris + go-auth integration
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

          {/* Navigation */}
          <div className="flex justify-between">
            <Button asChild variant="outline">
              <Link href="/frameworks">
                ← Back to Frameworks
              </Link>
            </Button>
            <Button asChild>
              <Link href="/quickstart">
                Next: Quick Start Guide →
              </Link>
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
} 