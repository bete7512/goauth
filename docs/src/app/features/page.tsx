"use client";

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Shield, Key, Lock, Zap, ShieldCheck, Users } from "lucide-react";
import Link from "next/link";

const FeaturesPage = () => {
  const features = [
    {
      title: "OAuth Providers",
      description: "Social login with Google, GitHub, Facebook, and more",
      icon: Users,
      href: "/features/oauth",
      color: "text-blue-600"
    },
    {
      title: "JWT Authentication",
      description: "Secure token-based authentication with customizable claims",
      icon: Key,
      href: "/features/jwt",
      color: "text-green-600"
    },
    {
      title: "Two-Factor Authentication",
      description: "Enhanced security with TOTP and SMS verification",
      icon: Lock,
      href: "/features/two-factor",
      color: "text-purple-600"
    },
    {
      title: "Rate Limiting",
      description: "Protect your API from abuse with configurable rate limits",
      icon: Zap,
      href: "/features/rate-limiting",
      color: "text-orange-600"
    },
    {
      title: "reCAPTCHA Integration",
      description: "Bot protection with Google reCAPTCHA and Cloudflare Turnstile",
      icon: ShieldCheck,
      href: "/features/recaptcha",
      color: "text-red-600"
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
            <h1 className="text-3xl font-bold mb-4">Features</h1>
            <p className="text-lg text-muted-foreground">
              Explore the powerful features that make go-auth the complete authentication solution for Go applications.
            </p>
          </header>

          {/* Features Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature) => (
              <Card key={feature.href} className="hover:shadow-lg transition-shadow">
                <CardHeader>
                  <div className="flex items-center space-x-3">
                    <feature.icon className={`h-8 w-8 ${feature.color}`} />
                    <CardTitle className="text-xl">{feature.title}</CardTitle>
                  </div>
                  <CardDescription className="text-base">
                    {feature.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <Button asChild className="w-full">
                    <Link href={feature.href}>
                      Learn More
                    </Link>
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Overview */}
          <Card className="mt-12">
            <CardHeader>
              <CardTitle>Why Choose go-auth?</CardTitle>
              <CardDescription>
                A comprehensive authentication solution designed for modern Go applications
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div>
                  <h3 className="font-semibold mb-2">Framework Agnostic</h3>
                  <p className="text-sm text-muted-foreground">
                    Works with Gin, Echo, Chi, Fiber, and any other Go web framework
                  </p>
                </div>
                <div>
                  <h3 className="font-semibold mb-2">Production Ready</h3>
                  <p className="text-sm text-muted-foreground">
                    Built with security best practices and comprehensive error handling
                  </p>
                </div>
                <div>
                  <h3 className="font-semibold mb-2">Easy Integration</h3>
                  <p className="text-sm text-muted-foreground">
                    Simple setup with minimal configuration required
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default FeaturesPage; 