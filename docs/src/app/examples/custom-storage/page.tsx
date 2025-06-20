"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield, Database, Copy } from "lucide-react";
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

const CustomStorageExample = () => (
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
            <Database className="h-8 w-8 text-green-600" />
            <h1 className="text-3xl font-bold">Custom Storage Example</h1>
          </div>
          <p className="text-lg text-muted-foreground">Use your own repository or storage backend with go-auth.</p>
        </header>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Configuration</CardTitle>
            <CardDescription>Enable custom storage and provide your repository</CardDescription>
          </CardHeader>
          <CardContent>
            <CodeBlock title="config.go">
{`config := types.Config{
  EnableCustomStorageRepository: true,
  // ...
}

repo := &MyCustomRepository{}
authService, err := goauth.NewBuilder().
  WithConfig(config).
  WithRepositoryFactory(repo).
  Build()`}
            </CodeBlock>
          </CardContent>
        </Card>
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Repository Example</CardTitle>
            <CardDescription>Implement the RepositoryFactory interface</CardDescription>
          </CardHeader>
          <CardContent>
            <CodeBlock title="MyCustomRepository.go">
{`type MyCustomRepository struct {}

func (r *MyCustomRepository) CreateUser(user *types.User) error {
  // ...
  return nil
}
// Implement other methods...`}
            </CodeBlock>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>More Examples</CardTitle>
            <CardDescription>Explore more usage patterns</CardDescription>
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
                <Link href="/examples/oauth-setup">
                  <span className="font-semibold">OAuth Setup</span>
                  <span className="text-sm text-muted-foreground mt-1">Enable social login</span>
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </main>
  </div>
);

export default CustomStorageExample; 