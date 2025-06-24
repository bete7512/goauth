"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield, Users, Copy } from "lucide-react";
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

const OAuthSetupExample = () => (
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
            <Users className="h-8 w-8 text-blue-600" />
            <h1 className="text-3xl font-bold">OAuth Setup Example</h1>
          </div>
          <p className="text-lg text-muted-foreground">Enable social login with Google, GitHub, and more using go-auth.</p>
        </header>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Configuration</CardTitle>
            <CardDescription>Enable OAuth providers in your config</CardDescription>
          </CardHeader>
          <CardContent>
            <CodeBlock title="config.go">
{`config := types.Config{
  Providers: types.ProvidersConfig{
    Enabled: []string{"google", "github"},
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
  },
}`}
            </CodeBlock>
          </CardContent>
        </Card>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Usage</CardTitle>
            <CardDescription>Start OAuth login from your frontend</CardDescription>
          </CardHeader>
          <CardContent>
            <CodeBlock title="Frontend Example (HTML)">
{`<a href="/auth/oauth/google">Sign in with Google</a>
<a href="/auth/oauth/github">Sign in with GitHub</a>`}
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
                <Link href="/examples/basic-auth">
                  <span className="font-semibold">Basic Auth</span>
                  <span className="text-sm text-muted-foreground mt-1">Username/password login</span>
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

export default OAuthSetupExample; 