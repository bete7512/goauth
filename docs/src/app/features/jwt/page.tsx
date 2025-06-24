"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield, Key, Copy } from "lucide-react";
import Link from "next/link";

const CodeBlock = ({ children, title }: { children: string; title?: string }) => {
  const copyToClipboard = (text: string) => navigator.clipboard.writeText(text);
  return (
    <div className="relative">
      {title && <div className="bg-muted/60 px-4 py-2 text-xs font-medium text-muted-foreground border-b">{title}</div>}
      <div className="bg-muted p-4 rounded-lg font-mono text-sm relative group">
        <button onClick={() => copyToClipboard(children)} className="absolute top-2 right-2 p-1 rounded opacity-0 group-hover:opacity-100 transition-opacity hover:bg-background" title="Copy to clipboard">
          <Copy className="h-4 w-4" />
        </button>
        <pre className="overflow-x-auto"><code className="text-foreground whitespace-pre">{children}</code></pre>
      </div>
    </div>
  );
};

const JWTPage = () => (
  <div className="flex min-h-screen">
    <aside className="w-64 border-r bg-muted/40">
      <div className="p-6">
        <div className="flex items-center space-x-2">
          <Shield className="h-6 w-6 text-primary" />
          <h1 className="text-xl font-bold">go-auth</h1>
        </div>
        <p className="mt-2 text-sm text-muted-foreground">Authentication library for Go</p>
      </div>
      <div className="p-4">
        <Link href="/features" className="flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="h-4 w-4 mr-2" />Back to Features
        </Link>
      </div>
    </aside>
    <main className="flex-1 overflow-auto">
      <div className="container mx-auto p-8 max-w-4xl">
        <header className="mb-8">
          <div className="flex items-center space-x-3 mb-4">
            <Key className="h-8 w-8 text-green-600" />
            <h1 className="text-3xl font-bold">JWT Authentication</h1>
          </div>
          <p className="text-lg text-muted-foreground">go-auth uses secure JWTs for stateless authentication, supporting custom claims and expiration.</p>
        </header>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Configuration</CardTitle>
            <CardDescription>Configure JWT settings in your go-auth config</CardDescription>
          </CardHeader>
          <CardContent>
            <CodeBlock title="config.go">
{`config := types.Config{
  JWTSecret: "your-super-secret-jwt-key",
  AuthConfig: types.AuthConfig{
    Cookie: types.CookieConfig{
      Name:           "auth_token",
      AccessTokenTTL: 3600,   // 1 hour
      RefreshTokenTTL: 604800, // 7 days
      Path:           "/",
      MaxAge:         604800,
      Secure:         false,
      HttpOnly:       true,
    },
  },
}`}
            </CodeBlock>
          </CardContent>
        </Card>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Usage</CardTitle>
            <CardDescription>JWTs are issued on login and used for protected routes</CardDescription>
          </CardHeader>
          <CardContent>
            <CodeBlock title="Example: Access Protected Route">
{`curl -X GET http://localhost:8080/api/profile \
  -H "Cookie: auth_token=YOUR_JWT_TOKEN"`}
            </CodeBlock>
          </CardContent>
        </Card>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Best Practices</CardTitle>
            <CardDescription>Keep your JWT secret safe and use HTTPS in production</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-6 text-sm text-muted-foreground space-y-2">
              <li>Use a strong, random JWT secret</li>
              <li>Set short expiration for access tokens</li>
              <li>Use HTTPS to protect tokens in transit</li>
              <li>Store tokens in HttpOnly cookies</li>
            </ul>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>What&apos;s Next?</CardTitle>
            <CardDescription>Explore more authentication features</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                <Link href="/features/two-factor">
                  <span className="font-semibold">Two-Factor Auth</span>
                  <span className="text-sm text-muted-foreground mt-1">Enhance security with 2FA</span>
                </Link>
              </Button>
              <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                <Link href="/features/rate-limiting">
                  <span className="font-semibold">Rate Limiting</span>
                  <span className="text-sm text-muted-foreground mt-1">Protect your API from abuse</span>
                </Link>
              </Button>
              <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                <Link href="/features/recaptcha">
                  <span className="font-semibold">reCAPTCHA</span>
                  <span className="text-sm text-muted-foreground mt-1">Bot protection for your endpoints</span>
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  </div>
);

export default JWTPage; 