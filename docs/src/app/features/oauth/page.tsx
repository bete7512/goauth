"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield, Globe, Github, ExternalLink, CheckCircle } from "lucide-react";
import { CodeBlock, CodeBlockWithLines } from "@/components/ui/code-block";
import Link from "next/link";

const OAuthPage = () => {
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
                <Globe className="h-3 w-3 mr-1" />
                OAuth Providers
              </Badge>
              <Badge variant="secondary" className="text-sm">
                <CheckCircle className="h-3 w-3 mr-1" />
                8 Providers
              </Badge>
            </div>
            <h1 className="text-3xl font-bold mb-4">OAuth Providers</h1>
            <p className="text-lg text-muted-foreground">
              Set up social login with popular OAuth providers including Google, GitHub, Facebook, and more.
            </p>
          </header>

          {/* Supported Providers */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Supported OAuth Providers</CardTitle>
              <CardDescription>
                Choose from 8 popular OAuth providers for social login
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="flex items-center space-x-2 p-3 border rounded-lg">
                  <div className="w-8 h-8 bg-red-500 rounded flex items-center justify-center">
                    <span className="text-white text-xs font-bold">G</span>
                  </div>
                  <span className="font-medium">Google</span>
                </div>
                <div className="flex items-center space-x-2 p-3 border rounded-lg">
                  <Github className="w-8 h-8" />
                  <span className="font-medium">GitHub</span>
                </div>
                <div className="flex items-center space-x-2 p-3 border rounded-lg">
                  <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center">
                    <span className="text-white text-xs font-bold">f</span>
                  </div>
                  <span className="font-medium">Facebook</span>
                </div>
                <div className="flex items-center space-x-2 p-3 border rounded-lg">
                  <div className="w-8 h-8 bg-blue-500 rounded flex items-center justify-center">
                    <span className="text-white text-xs font-bold">M</span>
                  </div>
                  <span className="font-medium">Microsoft</span>
                </div>
                <div className="flex items-center space-x-2 p-3 border rounded-lg">
                  <div className="w-8 h-8 bg-black rounded flex items-center justify-center">
                    <span className="text-white text-xs font-bold">A</span>
                  </div>
                  <span className="font-medium">Apple</span>
                </div>
                <div className="flex items-center space-x-2 p-3 border rounded-lg">
                  <div className="w-8 h-8 bg-indigo-600 rounded flex items-center justify-center">
                    <span className="text-white text-xs font-bold">D</span>
                  </div>
                  <span className="font-medium">Discord</span>
                </div>
                <div className="flex items-center space-x-2 p-3 border rounded-lg">
                  <div className="w-8 h-8 bg-blue-400 rounded flex items-center justify-center">
                    <span className="text-white text-xs font-bold">T</span>
                  </div>
                  <span className="font-medium">Twitter</span>
                </div>
                <div className="flex items-center space-x-2 p-3 border rounded-lg">
                  <div className="w-8 h-8 bg-blue-700 rounded flex items-center justify-center">
                    <span className="text-white text-xs font-bold">L</span>
                  </div>
                  <span className="font-medium">LinkedIn</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Configuration */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>OAuth Configuration</CardTitle>
              <CardDescription>
                Configure OAuth providers in your go-auth setup
              </CardDescription>
            </CardHeader>
            <CardContent>
              <CodeBlockWithLines language="go" title="OAuth Configuration">
{`config := config.Config{
    // ... other config
    
    Providers: config.ProvidersConfig{
        Enabled: []config.AuthProvider{
            config.Google,
            config.GitHub,
            config.Facebook,
            config.Microsoft,
            config.Apple,
            config.Discord,
            config.Twitter,
            config.LinkedIn,
        },
        
        // Google OAuth
        Google: config.ProviderConfig{
            ClientID:     "your-google-client-id",
            ClientSecret: "your-google-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
            Scopes:       []string{"email", "profile"},
        },
        
        // GitHub OAuth
        GitHub: config.ProviderConfig{
            ClientID:     "your-github-client-id",
            ClientSecret: "your-github-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/github/callback",
            Scopes:       []string{"user:email", "read:user"},
        },
        
        // Facebook OAuth
        Facebook: config.ProviderConfig{
            ClientID:     "your-facebook-client-id",
            ClientSecret: "your-facebook-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/facebook/callback",
            Scopes:       []string{"email", "public_profile"},
        },
        
        // Microsoft OAuth
        Microsoft: config.ProviderConfig{
            ClientID:     "your-microsoft-client-id",
            ClientSecret: "your-microsoft-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/microsoft/callback",
            Scopes:       []string{"user.read", "email"},
        },
        
        // Apple OAuth
        Apple: config.ProviderConfig{
            ClientID:     "your-apple-client-id",
            ClientSecret: "your-apple-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/apple/callback",
            Scopes:       []string{"email", "name"},
        },
        
        // Discord OAuth
        Discord: config.ProviderConfig{
            ClientID:     "your-discord-client-id",
            ClientSecret: "your-discord-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/discord/callback",
            Scopes:       []string{"identify", "email"},
        },
        
        // Twitter OAuth
        Twitter: config.ProviderConfig{
            ClientID:     "your-twitter-client-id",
            ClientSecret: "your-twitter-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/twitter/callback",
            Scopes:       []string{"tweet.read", "users.read"},
        },
        
        // LinkedIn OAuth
        LinkedIn: config.ProviderConfig{
            ClientID:     "your-linkedin-client-id",
            ClientSecret: "your-linkedin-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/linkedin/callback",
            Scopes:       []string{"r_liteprofile", "r_emailaddress"},
        },
    },
}`}
              </CodeBlockWithLines>
            </CardContent>
          </Card>

          {/* Setup Guides */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            
            {/* Google Setup */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <div className="w-8 h-8 bg-red-500 rounded flex items-center justify-center mr-3">
                    <span className="text-white text-sm font-bold">G</span>
                  </div>
                  Google OAuth Setup
                </CardTitle>
                <CardDescription>
                  Set up Google OAuth 2.0 for your application
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <p className="text-sm text-muted-foreground">
                    1. Go to Google Cloud Console and create a new project
                  </p>
                  <Button asChild variant="outline" size="sm">
                    <a href="https://console.cloud.google.com/" target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="h-4 w-4 mr-2" />
                      Google Cloud Console
                    </a>
                  </Button>
                  <p className="text-sm text-muted-foreground">
                    2. Enable Google+ API and OAuth 2.0 API
                  </p>
                  <p className="text-sm text-muted-foreground">
                    3. Create OAuth 2.0 credentials with redirect URI:
                  </p>
                  <CodeBlock language="text" title="Redirect URI">
                    http://localhost:8080/auth/oauth/google/callback
                  </CodeBlock>
                </div>
              </CardContent>
            </Card>

            {/* GitHub Setup */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Github className="w-8 h-8 mr-3" />
                  GitHub OAuth Setup
                </CardTitle>
                <CardDescription>
                  Set up GitHub OAuth for your application
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <p className="text-sm text-muted-foreground">
                    1. Go to GitHub Developer Settings
                  </p>
                  <Button asChild variant="outline" size="sm">
                    <a href="https://github.com/settings/developers" target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="h-4 w-4 mr-2" />
                      GitHub Developer Settings
                    </a>
                  </Button>
                  <p className="text-sm text-muted-foreground">
                    2. Create a new OAuth App
                  </p>
                  <p className="text-sm text-muted-foreground">
                    3. Set callback URL to:
                  </p>
                  <CodeBlock language="text" title="Callback URL">
                    http://localhost:8080/auth/oauth/github/callback
                  </CodeBlock>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Usage Example */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Frontend Integration</CardTitle>
              <CardDescription>
                Add OAuth login buttons to your frontend
              </CardDescription>
            </CardHeader>
            <CardContent>
              <CodeBlock language="html" title="OAuth Buttons">
{`<!-- Google OAuth Button -->
<a href="/auth/oauth/google" class="oauth-button google">
  <img src="/google-icon.svg" alt="Google" />
  Continue with Google
</a>

<!-- GitHub OAuth Button -->
<a href="/auth/oauth/github" class="oauth-button github">
  <svg><!-- GitHub icon --></svg>
  Continue with GitHub
</a>

<!-- Facebook OAuth Button -->
<a href="/auth/oauth/facebook" class="oauth-button facebook">
  <svg><!-- Facebook icon --></svg>
  Continue with Facebook
</a>

<!-- After OAuth callback, user will be redirected to your frontend
     with authentication cookies set automatically`}
              </CodeBlock>
            </CardContent>
          </Card>

          {/* Testing */}
          <Card>
            <CardHeader>
              <CardTitle>Testing OAuth</CardTitle>
              <CardDescription>
                Test your OAuth implementation
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-3">Test OAuth Flow</h4>
                  <CodeBlock language="bash" title="Test Commands">
{`# Test OAuth initiation
curl -I http://localhost:8080/auth/oauth/google

# Expected: 302 redirect to Google OAuth consent screen

# After successful OAuth login, check user profile
curl -X GET http://localhost:8080/auth/me \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\
  -H "Content-Type: application/json"`}
                  </CodeBlock>
                </div>
                
                <div>
                  <h4 className="font-semibold mb-3">Expected Response</h4>
                  <CodeBlock language="json" title="User Profile">
{`{
  "id": "user_id",
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "provider": "google",
  "providerId": "google_user_id",
  "emailVerified": true,
  "createdAt": "2024-01-01T00:00:00Z",
  "updatedAt": "2024-01-01T00:00:00Z"
}`}
                  </CodeBlock>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default OAuthPage; 