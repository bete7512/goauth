import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "go-auth Documentation",
  description: "A comprehensive authentication library for Go applications with support for multiple frameworks, OAuth providers, and advanced security features.",
  keywords: ["go", "authentication", "oauth", "jwt", "security", "golang"],
  authors: [{ name: "go-auth Team" }],
  openGraph: {
    title: "go-auth Documentation",
    description: "A comprehensive authentication library for Go applications",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        <div className="min-h-screen bg-background">
          {children}
        </div>
      </body>
    </html>
  );
}
