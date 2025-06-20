"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield, Copy } from "lucide-react";
import Link from "next/link";

// Code block component with syntax highlighting
const CodeBlock = ({ 
  children, 
  title 
}: { 
  children: string; 
  language?: string; 
  title?: string; 
}) => {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="relative">
      {title && (
        <div className="bg-muted/60 px-4 py-2 text-xs font-medium text-muted-foreground border-b">
          {title}
        </div>
      )}
      <div className="bg-muted p-4 rounded-lg font-mono text-sm relative group">
        <button
          onClick={() => copyToClipboard(children)}
          className="absolute top-2 right-2 p-1 rounded opacity-0 group-hover:opacity-100 transition-opacity hover:bg-background"
          title="Copy to clipboard"
        >
          <Copy className="h-4 w-4" />
        </button>
        <pre className="overflow-x-auto">
          <code className="text-foreground whitespace-pre">{children}</code>
        </pre>
      </div>
    </div>
  );
};

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
            <h1 className="text-3xl font-bold mb-4">Quick Start Guide</h1>
            <p className="text-lg text-muted-foreground">
              Build your first authenticated application with go-auth in minutes.
            </p>
          </header>

          {/* Installation */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Installation</CardTitle>
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
{`go get github.com/gin-gonic/gin
# or
go get github.com/labstack/echo/v4
# or
go get github.com/go-chi/chi/v5
# or
go get github.com/gofiber/fiber/v2`}
                  </CodeBlock>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Basic Setup */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Basic Setup</CardTitle>
              <CardDescription>
                Create a simple authentication server
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h3 className="text-lg font-semibold mb-3">Create main.go</h3>
                  <CodeBlock language="go" title="main.go">
{`package main

import (
    "log"
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
    "github.com/gin-gonic/gin"
)

func main() {
    config := types.Config{
        JWTSecret: "your-secret-key",
        Database: types.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:pass@localhost/db",
        },
    }
    
    authService, err := goauth.NewBuilder().WithConfig(config).Build()
    if err != nil {
        log.Fatal("Failed to create auth service:", err)
    }
    
    router := gin.Default()
    authService.RegisterGinRoutes(router)
    
    log.Println("Server starting on :8080")
    router.Run(":8080")
}`}
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
                  <h4 className="font-semibold mb-3">1. Start your server</h4>
                  <CodeBlock language="bash" title="Terminal">
                    go run main.go
                  </CodeBlock>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-3">2. Register a user</h4>
                  <CodeBlock language="bash" title="cURL Command">
{`curl -X POST http://localhost:8080/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'`}
                  </CodeBlock>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-3">3. Login</h4>
                  <CodeBlock language="bash" title="cURL Command">
{`curl -X POST http://localhost:8080/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'`}
                  </CodeBlock>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Next Steps */}
          <Card>
            <CardHeader>
              <CardTitle>What&apos;s Next?</CardTitle>
              <CardDescription>
                Explore more advanced features and configurations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/frameworks">
                    <span className="font-semibold">Framework Guides</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Detailed guides for each framework
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
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/installation">
                    <span className="font-semibold">Installation</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Complete installation guide
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
};

export default QuickstartPage;