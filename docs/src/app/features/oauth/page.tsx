"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ArrowLeft, Shield, Users, ExternalLink, Copy } from "lucide-react";
import Link from "next/link";

// Code block component
const CodeBlock = ({ 
  children, 
  title 
}: { 
  children: string; 
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

const OAuthPage = () => {
  const providers = [
    {
      name: "Google",
      description: "Sign in with Google accounts",
      status: "Supported",
      color: "bg-blue-100 text-blue-800"
    },
    {
      name: "GitHub",
      description: "Sign in with GitHub accounts",
      status: "Supported",
      color: "bg-gray-100 text-gray-800"
    },
    {
      name: "Facebook",
      description: "Sign in with Facebook accounts",
      status: "Supported",
      color: "bg-blue-100 text-blue-800"
    },
    {
      name: "Microsoft",
      description: "Sign in with Microsoft accounts",
      status: "Supported",
      color: "bg-green-100 text-green-800"
    },
    {
      name: "Apple",
      description: "Sign in with Apple accounts",
      status: "Supported",
      color: "bg-black text-white"
    },
    {
      name: "Discord",
      description: "Sign in with Discord accounts",
      status: "Supported",
      color: "bg-purple-100 text-purple-800"
    },
    {
      name: "Twitter",
      description: "Sign in with Twitter accounts",
      status: "Supported",
      color: "bg-blue-100 text-blue-800"
    },
    {
      name: "LinkedIn",
      description: "Sign in with LinkedIn accounts",
      status: "Supported",
      color: "bg-blue-100 text-blue-800"
    }
  ];

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
          <Link href="/features" className="flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Features
          </Link>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <div className="container mx-auto p-8 max-w-4xl">
          <header className="mb-8">
            <div className="flex items-center space-x-3 mb-4">
              <Users className="h-8 w-8 text-blue-600" />
              <h1 className="text-3xl font-bold">OAuth Providers</h1>
            </div>
            <p className="text-lg text-muted-foreground">
              Enable social login with popular OAuth providers. Users can sign in with their existing accounts from Google, GitHub, Facebook, and more.
            </p>
          </header>

          {/* Supported Providers */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Supported Providers</CardTitle>
              <CardDescription>
                All major OAuth providers are supported out of the box
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {providers.map((provider) => (
                  <div key={provider.name} className="flex items-center justify-between p-4 border rounded-lg">
                    <div>
                      <h3 className="font-semibold">{provider.name}</h3>
                      <p className="text-sm text-muted-foreground">{provider.description}</p>
                    </div>
                    <Badge className={provider.color}>{provider.status}</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Configuration */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Configuration</CardTitle>
              <CardDescription>
                Set up OAuth providers in your application
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="config" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="config">Configuration</TabsTrigger>
                  <TabsTrigger value="setup">Setup</TabsTrigger>
                  <TabsTrigger value="usage">Usage</TabsTrigger>
                </TabsList>
                
                <TabsContent value="config" className="mt-6">
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-3">Provider Configuration</h3>
                      <CodeBlock title="config.go">
{`config := types.Config{
    // ... other config
    
    Providers: types.ProvidersConfig{
        Enabled: []string{
            "google",
            "github",
            "facebook",
        },
        Google: types.ProviderConfig{
            ClientID:     "your-google-client-id",
            ClientSecret: "your-google-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
        },
        GitHub: types.ProviderConfig{
            ClientID:     "your-github-client-id",
            ClientSecret: "your-github-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/github/callback",
        },
        Facebook: types.ProviderConfig{
            ClientID:     "your-facebook-client-id",
            ClientSecret: "your-facebook-client-secret",
            RedirectURL:  "http://localhost:8080/auth/oauth/facebook/callback",
        },
    },
}`}
                      </CodeBlock>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="setup" className="mt-6">
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-3">1. Create OAuth App</h3>
                      <div className="space-y-4">
                        <div className="p-4 border rounded-lg">
                          <h4 className="font-semibold mb-2">Google</h4>
                          <p className="text-sm text-muted-foreground mb-2">
                            1. Go to <a href="https://console.developers.google.com" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Google Cloud Console</a>
                          </p>
                          <p className="text-sm text-muted-foreground mb-2">
                            2. Create a new project or select existing one
                          </p>
                          <p className="text-sm text-muted-foreground mb-2">
                            3. Enable Google+ API
                          </p>
                          <p className="text-sm text-muted-foreground">
                            4. Create OAuth 2.0 credentials
                          </p>
                        </div>
                        
                        <div className="p-4 border rounded-lg">
                          <h4 className="font-semibold mb-2">GitHub</h4>
                          <p className="text-sm text-muted-foreground mb-2">
                            1. Go to <a href="https://github.com/settings/developers" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">GitHub Developer Settings</a>
                          </p>
                          <p className="text-sm text-muted-foreground mb-2">
                            2. Click "New OAuth App"
                          </p>
                          <p className="text-sm text-muted-foreground mb-2">
                            3. Fill in application details
                          </p>
                          <p className="text-sm text-muted-foreground">
                            4. Set callback URL to your application
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="usage" className="mt-6">
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-3">Frontend Integration</h3>
                      <CodeBlock title="login.html">
{`<!-- OAuth Login Buttons -->
<div class="oauth-buttons">
  <a href="/auth/oauth/google" class="btn btn-google">
    Sign in with Google
  </a>
  <a href="/auth/oauth/github" class="btn btn-github">
    Sign in with GitHub
  </a>
  <a href="/auth/oauth/facebook" class="btn btn-facebook">
    Sign in with Facebook
  </a>
</div>`}
                      </CodeBlock>
                    </div>
                    
                    <div>
                      <h3 className="text-lg font-semibold mb-3">Handle Callback</h3>
                      <CodeBlock title="callback.js">
{`// The OAuth callback is handled automatically by go-auth
// Users will be redirected to your application after successful authentication
// You can customize the redirect URL in your configuration

// Example: Redirect to dashboard after login
window.location.href = '/dashboard';`}
                      </CodeBlock>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          {/* Security Best Practices */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Security Best Practices</CardTitle>
              <CardDescription>
                Follow these guidelines to ensure secure OAuth implementation
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                  <div>
                    <h4 className="font-semibold">Use HTTPS in Production</h4>
                    <p className="text-sm text-muted-foreground">
                      Always use HTTPS for OAuth redirect URLs in production environments
                    </p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                  <div>
                    <h4 className="font-semibold">Secure Client Secrets</h4>
                    <p className="text-sm text-muted-foreground">
                      Store client secrets securely using environment variables or secret management systems
                    </p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                  <div>
                    <h4 className="font-semibold">Validate Redirect URLs</h4>
                    <p className="text-sm text-muted-foreground">
                      Ensure redirect URLs match exactly what's configured in your OAuth provider
                    </p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-3">
                  <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                  <div>
                    <h4 className="font-semibold">Handle State Parameter</h4>
                    <p className="text-sm text-muted-foreground">
                      Use state parameters to prevent CSRF attacks (handled automatically by go-auth)
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Next Steps */}
          <Card>
            <CardHeader>
              <CardTitle>What&apos;s Next?</CardTitle>
              <CardDescription>
                Continue exploring other authentication features
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/features/jwt">
                    <span className="font-semibold">JWT Authentication</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Learn about token-based authentication
                    </span>
                  </Link>
                </Button>
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/features/two-factor">
                    <span className="font-semibold">Two-Factor Auth</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Enhance security with 2FA
                    </span>
                  </Link>
                </Button>
                <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                  <Link href="/features/rate-limiting">
                    <span className="font-semibold">Rate Limiting</span>
                    <span className="text-sm text-muted-foreground mt-1">
                      Protect your API from abuse
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

export default OAuthPage; 