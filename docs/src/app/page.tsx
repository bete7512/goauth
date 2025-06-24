import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  BookOpen, 
  Shield, 
  Code, 
  Zap, 
  Github, 
  Globe, 
  Lock, 
  Users,
  ArrowRight,
  Star
} from "lucide-react";
import Link from "next/link";

export default function Home() {
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
        
        <ScrollArea className="h-[calc(100vh-120px)]">
          <nav className="p-4 space-y-2">
            <div className="space-y-1">
              <h3 className="text-sm font-medium text-muted-foreground">Getting Started</h3>
              <Link href="/installation" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Installation
              </Link>
              <Link href="/quickstart" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Quick Start
              </Link>
              <Link href="/configuration" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Configuration
              </Link>
            </div>
            
            <Separator />
            
            <div className="space-y-1">
              <h3 className="text-sm font-medium text-muted-foreground">Frameworks</h3>
              <Link href="/frameworks/gin" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Gin
              </Link>
              <Link href="/frameworks/echo" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Echo
              </Link>
              <Link href="/frameworks/chi" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Chi
              </Link>
              <Link href="/frameworks/fiber" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Fiber
              </Link>
              <Link href="/frameworks/gorilla-mux" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Gorilla Mux
              </Link>
              <Link href="/frameworks/iris" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Iris
              </Link>
            </div>
            
            <Separator />
            
            <div className="space-y-1">
              <h3 className="text-sm font-medium text-muted-foreground">Features</h3>
              <Link href="/features/oauth" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                OAuth Providers
              </Link>
              <Link href="/features/jwt" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                JWT Authentication
              </Link>
              <Link href="/features/two-factor" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Two-Factor Auth
              </Link>
              <Link href="/features/rate-limiting" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Rate Limiting
              </Link>
              <Link href="/features/recaptcha" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                reCAPTCHA
              </Link>
            </div>
            
            <Separator />
            
            <div className="space-y-1">
              <h3 className="text-sm font-medium text-muted-foreground">API Reference</h3>
              <Link href="/api/endpoints" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Endpoints
              </Link>
              <Link href="/api/models" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Models
              </Link>
              <Link href="/api/hooks" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Hooks
              </Link>
            </div>
            
            <Separator />
            
            <div className="space-y-1">
              <h3 className="text-sm font-medium text-muted-foreground">Examples</h3>
              <Link href="/examples/basic-auth" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Basic Authentication
              </Link>
              <Link href="/examples/oauth-setup" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                OAuth Setup
              </Link>
              <Link href="/examples/custom-storage" className="block px-3 py-2 text-sm rounded-md hover:bg-muted">
                Custom Storage
              </Link>
            </div>
          </nav>
        </ScrollArea>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <div className="container mx-auto p-8">
          {/* Hero Section */}
          <div className="text-center mb-12">
            <div className="flex items-center justify-center mb-4">
              <Shield className="h-12 w-12 text-primary mr-3" />
              <h1 className="text-4xl font-bold">go-auth</h1>
            </div>
            <p className="text-xl text-muted-foreground mb-6 max-w-2xl mx-auto">
              A comprehensive authentication library for Go applications with support for multiple frameworks, 
              OAuth providers, and advanced security features.
            </p>
            <div className="flex items-center justify-center space-x-4 mb-8">
              <Badge variant="secondary" className="text-sm">
                <Star className="h-3 w-3 mr-1" />
                Production Ready
              </Badge>
              <Badge variant="secondary" className="text-sm">
                <Zap className="h-3 w-3 mr-1" />
                High Performance
              </Badge>
              <Badge variant="secondary" className="text-sm">
                <Shield className="h-3 w-3 mr-1" />
                Secure by Default
              </Badge>
            </div>
            <div className="flex items-center justify-center space-x-4">
              <Button asChild size="lg">
                <Link href="/quickstart">
                  Get Started
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
              <Button variant="outline" asChild size="lg">
                <a href="https://github.com/bete7512/goauth" target="_blank" rel="noopener noreferrer">
                  <Github className="mr-2 h-4 w-4" />
                  View on GitHub
                </a>
              </Button>
            </div>
          </div>

          {/* Features Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
            <Card>
              <CardHeader>
                <Globe className="h-8 w-8 text-primary mb-2" />
                <CardTitle>Multiple Frameworks</CardTitle>
                <CardDescription>
                  Support for Gin, Echo, Chi, Fiber, Gorilla Mux, and Iris
                </CardDescription>
              </CardHeader>
            </Card>

            <Card>
              <CardHeader>
                <Users className="h-8 w-8 text-primary mb-2" />
                <CardTitle>OAuth Providers</CardTitle>
                <CardDescription>
                  Google, GitHub, Facebook, Microsoft, Apple, Discord, and more
                </CardDescription>
              </CardHeader>
            </Card>

            <Card>
              <CardHeader>
                <Lock className="h-8 w-8 text-primary mb-2" />
                <CardTitle>Advanced Security</CardTitle>
                <CardDescription>
                  JWT, Two-Factor Auth, Rate Limiting, and reCAPTCHA
                </CardDescription>
              </CardHeader>
            </Card>

            <Card>
              <CardHeader>
                <Code className="h-8 w-8 text-primary mb-2" />
                <CardTitle>Easy Integration</CardTitle>
                <CardDescription>
                  Simple API with comprehensive documentation and examples
                </CardDescription>
              </CardHeader>
            </Card>

            <Card>
              <CardHeader>
                <Zap className="h-8 w-8 text-primary mb-2" />
                <CardTitle>High Performance</CardTitle>
                <CardDescription>
                  Optimized for speed with minimal memory footprint
                </CardDescription>
              </CardHeader>
            </Card>

            <Card>
              <CardHeader>
                <BookOpen className="h-8 w-8 text-primary mb-2" />
                <CardTitle>Extensible</CardTitle>
                <CardDescription>
                  Custom hooks, storage adapters, and JWT claims
                </CardDescription>
              </CardHeader>
            </Card>
          </div>

          {/* Quick Start Section */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Quick Start</CardTitle>
              <CardDescription>
                Get up and running with go-auth in minutes
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                <div className="text-muted-foreground mb-2"># Install the library</div>
                <div className="text-foreground">go get github.com/bete7512/goauth</div>
                <br />
                <div className="text-muted-foreground mb-2"># Basic usage with Gin</div>
                <div className="text-foreground">
                  {`package main

import (
    "github.com/bete7512/goauth"
    "github.com/gin-gonic/gin"
)

func main() {
    config := goauth.Config{
        JWTSecret: "your-secret-key",
        // ... other config
    }
    
    auth := goauth.New(config)
    router := gin.Default()
    
    // Register auth routes
    auth.RegisterGinRoutes(router)
    
    router.Run(":8080")
}`}
                </div>
              </div>
              <div className="mt-4">
                <Button asChild>
                  <Link href="/quickstart">
                    View Full Quick Start Guide
                    <ArrowRight className="ml-2 h-4 w-4" />
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
