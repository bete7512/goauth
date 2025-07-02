"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield, User, Copy } from "lucide-react";
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

const BasicAuthExample = () => (
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
        <Link href="/examples" className="flex items-center text-sm text-muted-foreground hover:text-foreground transition-colors">
          <ArrowLeft className="h-4 w-4 mr-2" />Back to Examples
        </Link>
      </div>
    </aside>
    <main className="flex-1 overflow-auto">
      <div className="container mx-auto p-8 max-w-4xl">
        <header className="mb-8">
          <div className="flex items-center space-x-3 mb-4">
            <User className="h-8 w-8 text-blue-600" />
            <h1 className="text-3xl font-bold">Basic Auth Example</h1>
          </div>
          <p className="text-lg text-muted-foreground">Minimal setup for username/password authentication with go-auth.</p>
        </header>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Configuration</CardTitle>
            <CardDescription>Basic config for password authentication</CardDescription>
          </CardHeader>
          <CardContent>
            <CodeBlock title="config.go">
{`config := types.Config{
  JWTSecret: "your-secret-key",
  Database: types.DatabaseConfig{
    Type: "postgres",
    URL:  "postgres://user:pass@localhost/db",
  },
}`}
            </CodeBlock>
          </CardContent>
        </Card>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Usage</CardTitle>
            <CardDescription>Register and login with username/password</CardDescription>
          </CardHeader>
          <CardContent>
            <CodeBlock title="Register User">
{`curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'`}
            </CodeBlock>
            <CodeBlock title="Login User">
{`curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'`}
            </CodeBlock>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>More Examples</CardTitle>
            <CardDescription>Explore more advanced usage</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                <Link href="/examples/oauth-setup">
                  <span className="font-semibold">OAuth Setup</span>
                  <span className="text-sm text-muted-foreground mt-1">Enable social login</span>
                </Link>
              </Button>
              <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                <Link href="/examples/custom-storage">
                  <span className="font-semibold">Custom Storage</span>
                  <span className="text-sm text-muted-foreground mt-1">Use your own repository</span>
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  </div>
);

export default BasicAuthExample; 