"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield, Globe, Copy } from "lucide-react";
import Link from "next/link";

const endpoints = [
  {
    path: "/auth/register",
    method: "POST",
    description: "Register a new user",
    example: `curl -X POST http://localhost:8080/auth/register \\n  -H "Content-Type: application/json" \\n  -d '{"email":"user@example.com","password":"password123"}'`,
    response: `{"id": "...", "email": "user@example.com", ...}`
  },
  {
    path: "/auth/login",
    method: "POST",
    description: "Login and receive tokens",
    example: `curl -X POST http://localhost:8080/auth/login \\n  -H "Content-Type: application/json" \\n  -d '{"email":"user@example.com","password":"password123"}'`,
    response: `{"accessToken": "...", "refreshToken": "..."}`
  },
  {
    path: "/auth/logout",
    method: "POST",
    description: "Logout and invalidate tokens",
    example: `curl -X POST http://localhost:8080/auth/logout` ,
    response: `{"message": "Logged out"}`
  },
  {
    path: "/auth/refresh-token",
    method: "POST",
    description: "Refresh access token",
    example: `curl -X POST http://localhost:8080/auth/refresh-token \\n  -H "Cookie: refresh_token=..."`,
    response: `{"accessToken": "..."}`
  },
  {
    path: "/auth/me",
    method: "GET",
    description: "Get current user profile",
    example: `curl -X GET http://localhost:8080/auth/me \\n  -H "Cookie: auth_token=..."`,
    response: `{"id": "...", "email": "user@example.com", ...}`
  },
  {
    path: "/auth/oauth/:provider",
    method: "GET",
    description: "Start OAuth login with a provider",
    example: `curl -X GET http://localhost:8080/auth/oauth/google`,
    response: `302 Redirect to provider login`
  },
  {
    path: "/auth/two-factor/verify",
    method: "POST",
    description: "Verify two-factor code",
    example: `curl -X POST http://localhost:8080/auth/two-factor/verify \\n  -H "Content-Type: application/json" \\n  -d '{"code":"123456"}'`,
    response: `{"message": "2FA verified"}`
  }
];

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

const EndpointsPage = () => (
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
        <Link href="/api" className="flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="h-4 w-4 mr-2" />Back to API Docs
        </Link>
      </div>
    </aside>
    <main className="flex-1 overflow-auto">
      <div className="container mx-auto p-8 max-w-4xl">
        <header className="mb-8">
          <div className="flex items-center space-x-3 mb-4">
            <Globe className="h-8 w-8 text-blue-600" />
            <h1 className="text-3xl font-bold">API Endpoints</h1>
          </div>
          <p className="text-lg text-muted-foreground">All available authentication endpoints with example requests and responses.</p>
        </header>
        {endpoints.map((ep) => (
          <Card className="mb-6" key={ep.path}>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <span className="text-base font-mono px-2 py-1 rounded bg-muted/60 border text-primary font-semibold">{ep.method}</span>
                <span>{ep.path}</span>
              </CardTitle>
              <CardDescription>{ep.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <CodeBlock title="Example Request">{ep.example}</CodeBlock>
              <CodeBlock title="Example Response">{ep.response}</CodeBlock>
            </CardContent>
          </Card>
        ))}
        <Card className="mt-12">
          <CardHeader>
            <CardTitle>More API Docs</CardTitle>
            <CardDescription>Explore models and hooks</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                <Link href="/api/models">
                  <span className="font-semibold">API Models</span>
                  <span className="text-sm text-muted-foreground mt-1">User, Token, and more</span>
                </Link>
              </Button>
              <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                <Link href="/api/hooks">
                  <span className="font-semibold">API Hooks</span>
                  <span className="text-sm text-muted-foreground mt-1">Customize authentication flow</span>
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  </div>
);

export default EndpointsPage; 