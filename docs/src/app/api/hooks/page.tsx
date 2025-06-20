"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield, Zap, Copy } from "lucide-react";
import Link from "next/link";

const hooks = [
  {
    name: "BeforeRegister",
    description: "Called before a user is registered.",
    signature: `func(user *types.User) error { ... }`
  },
  {
    name: "AfterLogin",
    description: "Called after a user successfully logs in.",
    signature: `func(user *types.User) error { ... }`
  },
  {
    name: "BeforeTokenRefresh",
    description: "Called before a refresh token is issued.",
    signature: `func(user *types.User) error { ... }`
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

const HooksPage = () => (
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
            <Zap className="h-8 w-8 text-yellow-600" />
            <h1 className="text-3xl font-bold">API Hooks</h1>
          </div>
          <p className="text-lg text-muted-foreground">Customize authentication flow by registering hooks for key events.</p>
        </header>
        {hooks.map((hook) => (
          <Card className="mb-6" key={hook.name}>
            <CardHeader>
              <CardTitle>{hook.name}</CardTitle>
              <CardDescription>{hook.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <CodeBlock title="Signature">{hook.signature}</CodeBlock>
            </CardContent>
          </Card>
        ))}
        <Card className="mt-12">
          <CardHeader>
            <CardTitle>More API Docs</CardTitle>
            <CardDescription>Explore endpoints and models</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                <Link href="/api/endpoints">
                  <span className="font-semibold">API Endpoints</span>
                  <span className="text-sm text-muted-foreground mt-1">All available endpoints</span>
                </Link>
              </Button>
              <Button asChild variant="outline" className="h-auto p-4 flex flex-col items-start">
                <Link href="/api/models">
                  <span className="font-semibold">API Models</span>
                  <span className="text-sm text-muted-foreground mt-1">User, Token, and more</span>
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  </div>
);

export default HooksPage; 