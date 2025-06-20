import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Download, Database, Shield } from "lucide-react";
import Link from "next/link";

export default function InstallationPage() {
  return (
    <div className="flex min-h-screen">
      {/* Sidebar - Same as main page */}
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
          <Link href="/" className="flex items-center text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Home
          </Link>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <div className="container mx-auto p-8 max-w-4xl">
          <div className="mb-8">
            <h1 className="text-3xl font-bold mb-4">Installation</h1>
            <p className="text-lg text-muted-foreground">
              Get go-auth up and running in your Go project with these simple steps.
            </p>
          </div>

          {/* Prerequisites */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Download className="h-5 w-5 mr-2" />
                Prerequisites
              </CardTitle>
              <CardDescription>
                Make sure you have the following installed before proceeding
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center space-x-3">
                  <Badge variant="outline">Go 1.21+</Badge>
                  <span className="text-sm text-muted-foreground">
                    Required for modern Go features and performance
                  </span>
                </div>
                <div className="flex items-center space-x-3">
                  <Badge variant="outline">Database</Badge>
                  <span className="text-sm text-muted-foreground">
                    PostgreSQL, MySQL, or MongoDB for user storage
                  </span>
                </div>
                <div className="flex items-center space-x-3">
                  <Badge variant="outline">Redis (Optional)</Badge>
                  <span className="text-sm text-muted-foreground">
                    For session storage and rate limiting
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Installation Steps */}
          <div className="space-y-8">
            {/* Step 1: Install the library */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <span className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold mr-3">
                    1
                  </span>
                  Install the Library
                </CardTitle>
                <CardDescription>
                  Add go-auth to your Go project
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                  <div className="text-muted-foreground mb-2"># Using go get</div>
                  <div className="text-foreground">go get github.com/bete7512/goauth</div>
                  <br />
                  <div className="text-muted-foreground mb-2"># Or using go mod</div>
                  <div className="text-foreground">go mod tidy</div>
                </div>
              </CardContent>
            </Card>

            {/* Step 2: Import the library */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <span className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold mr-3">
                    2
                  </span>
                  Import the Library
                </CardTitle>
                <CardDescription>
                  Add the import statement to your Go file
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                  <div className="text-foreground">
                    {`package main

import (
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
)`}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Step 3: Configure the library */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <span className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold mr-3">
                    3
                  </span>
                  Configure the Library
                </CardTitle>
                <CardDescription>
                  Set up the configuration for your authentication needs
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                  <div className="text-foreground">
                    {`config := types.Config{
    JWTSecret: "your-super-secret-jwt-key",
    Database: types.DatabaseConfig{
        Type: "postgres",
        URL:  "postgres://user:password@localhost:5432/dbname",
    },
    AuthConfig: types.AuthConfig{
        Cookie: types.CookieConfig{
            Name:           "auth_token",
            AccessTokenTTL: 3600,  // 1 hour
            RefreshTokenTTL: 604800, // 7 days
            Path:           "/",
            MaxAge:         604800,
        },
    },
}`}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Step 4: Initialize the service */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <span className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold mr-3">
                    4
                  </span>
                  Initialize the Service
                </CardTitle>
                <CardDescription>
                  Create and configure the authentication service
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                  <div className="text-foreground">
                    {`// Using the builder pattern
authService, err := goauth.NewBuilder().
    WithConfig(config).
    Build()

if err != nil {
    log.Fatal("Failed to create auth service:", err)
}`}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Step 5: Register routes */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <span className="bg-primary text-primary-foreground rounded-full w-6 h-6 flex items-center justify-center text-sm font-bold mr-3">
                    5
                  </span>
                  Register Routes
                </CardTitle>
                <CardDescription>
                  Add authentication routes to your web framework
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <h4 className="font-semibold mb-2">Gin Framework</h4>
                    <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                      <div className="text-foreground">
                        {`router := gin.Default()
authService.RegisterGinRoutes(router)`}
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <h4 className="font-semibold mb-2">Echo Framework</h4>
                    <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                      <div className="text-foreground">
                        {`e := echo.New()
authService.RegisterEchoRoutes(e)`}
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <h4 className="font-semibold mb-2">Chi Framework</h4>
                    <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                      <div className="text-foreground">
                        {`r := chi.NewRouter()
authService.RegisterChiRoutes(r)`}
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Next Steps */}
          <Card className="mt-8">
            <CardHeader>
              <CardTitle>What's Next?</CardTitle>
              <CardDescription>
                Continue with these guides to get the most out of go-auth
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/quickstart">
                    <span className="font-semibold">Quick Start Guide</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Build your first authenticated application
                    </span>
                  </Link>
                </Button>
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/configuration">
                    <span className="font-semibold">Configuration</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Learn about all configuration options
                    </span>
                  </Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
} 